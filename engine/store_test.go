// Copyright 2023 Adevinta

package engine

import (
	"os"
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
