// Copyright 2023 Adevinta

package engine

import (
	"os"
	"regexp"
	"testing"
	"time"

	report "github.com/adevinta/vulcan-report"
	"github.com/google/go-cmp/cmp"
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
		report  report.Report
		regexps []*regexp.Regexp
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
			regexps: []*regexp.Regexp{
				regexp.MustCompile(`vulcan-semgrep.*https://example.com.*RUNNING`),
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
			regexps: []*regexp.Regexp{
				regexp.MustCompile(`vulcan-semgrep.*https://example.com.*RUNNING`),
				regexp.MustCompile(`vulcan-trivy.*https://example.org.*RUNNING`),
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
			regexps: []*regexp.Regexp{
				regexp.MustCompile(`vulcan-semgrep.*https://example.com.*FINISHED`),
				regexp.MustCompile(`vulcan-trivy.*https://example.org.*RUNNING`),
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

		for _, re := range update.regexps {
			if got := rs.Summary(); !re.MatchString(got) {
				t.Errorf("unmatched regexp %q:\n%v", re, got)
			}
		}
	}
}
