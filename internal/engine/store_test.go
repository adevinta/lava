// Copyright 2023 Adevinta

package engine

import (
	"os"
	"testing"
	"time"

	report "github.com/adevinta/vulcan-report"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestReportStoreUploadCheckData(t *testing.T) {
	testdata := []struct {
		kind       string
		file       string
		wantNilErr bool
	}{
		{
			kind:       "reports",
			file:       "testdata/store/empty_report.json",
			wantNilErr: true,
		},
		{
			kind:       "reports",
			file:       "testdata/store/invalid_report.json",
			wantNilErr: false,
		},
		{
			kind:       "logs",
			file:       "testdata/store/log.txt",
			wantNilErr: true,
		},
		{
			kind:       "reports",
			file:       "testdata/store/report.json",
			wantNilErr: true,
		},
		{
			kind:       "unknown",
			wantNilErr: false,
		},
	}

	var (
		want  = make(map[string]report.Report)
		store reportStore
	)
	for _, td := range testdata {
		var (
			content []byte
			rep     report.Report
		)

		if td.file != "" {
			var err error
			if content, err = os.ReadFile(td.file); err != nil {
				t.Fatalf("error reading file: %v", err)
			}

			if err := rep.UnmarshalJSONTimeAsString(content); err == nil {
				want[rep.CheckID] = rep
			}
		}

		link, err := store.UploadCheckData(rep.CheckID, td.kind, time.Time{}, content)

		if (err == nil) != td.wantNilErr {
			t.Errorf("unexpected error: %v", err)
		}

		if link != "" {
			t.Errorf("unexpected link: %v", link)
		}
	}

	if diff := cmp.Diff(want, store.reports); diff != "" {
		t.Errorf("reports mismatch (-want +got):\n%v", diff)
	}
}

func TestReportStoreSummary(t *testing.T) {
	updates := []struct {
		report report.Report
		want   []string
	}{
		{
			report: report.Report{
				CheckData: report.CheckData{
					Target:        "https://example.com/",
					CheckID:       "check1",
					Status:        "RUNNING",
					ChecktypeName: "vulcan-semgrep",
				},
			},
			want: []string{
				`checktype=vulcan-semgrep target=https://example.com/ start=0001-01-01 00:00:00 +0000 UTC status=RUNNING`,
			},
		},
		{
			report: report.Report{
				CheckData: report.CheckData{
					Target:        "https://example.org/",
					CheckID:       "check2",
					Status:        "RUNNING",
					ChecktypeName: "vulcan-trivy",
				},
			},
			want: []string{
				`checktype=vulcan-semgrep target=https://example.com/ start=0001-01-01 00:00:00 +0000 UTC status=RUNNING`,
				`checktype=vulcan-trivy target=https://example.org/ start=0001-01-01 00:00:00 +0000 UTC status=RUNNING`,
			},
		},
		{
			report: report.Report{
				CheckData: report.CheckData{
					Target:        "https://example.com/",
					CheckID:       "check1",
					Status:        "FINISHED",
					ChecktypeName: "vulcan-semgrep",
				},
			},
			want: []string{
				`checktype=vulcan-semgrep target=https://example.com/ start=0001-01-01 00:00:00 +0000 UTC status=FINISHED`,
				`checktype=vulcan-trivy target=https://example.org/ start=0001-01-01 00:00:00 +0000 UTC status=RUNNING`,
			},
		},
	}

	var rs reportStore
	for _, update := range updates {
		content, err := update.report.MarshalJSONTimeAsString()
		if err != nil {
			t.Fatalf("unexpected marshal error: %v", err)
		}
		if _, err := rs.UploadCheckData(update.report.CheckID, "reports", time.Now(), content); err != nil {
			t.Fatalf("unexpected upload error: %v", err)
		}

		got := rs.Summary()

		opt := cmpopts.SortSlices(func(a, b string) bool { return a < b })
		if diff := cmp.Diff(update.want, got, opt); diff != "" {
			t.Errorf("summaries mismatch (-want +got):\n%v", diff)
		}
	}
}
