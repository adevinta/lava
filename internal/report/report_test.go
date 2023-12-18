// Copyright 2023 Adevinta

package report

import (
	"fmt"
	"os"
	"path"
	"testing"

	vreport "github.com/adevinta/vulcan-report"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/adevinta/lava/internal/config"
	"github.com/adevinta/lava/internal/engine"
)

func TestWriter_calculateExitCode(t *testing.T) {
	tests := []struct {
		name    string
		sum     summary
		status  []checkStatus
		rConfig config.ReportConfig
		want    ExitCode
	}{
		{
			name: "critical",
			sum: summary{
				count: map[config.Severity]int{
					config.SeverityCritical: 1,
					config.SeverityHigh:     1,
					config.SeverityMedium:   1,
					config.SeverityLow:      1,
					config.SeverityInfo:     1,
				},
			},
			status: []checkStatus{
				{
					Checktype: "Checktype1",
					Target:    "Target1",
					Status:    "FINISHED",
				},
			},
			rConfig: config.ReportConfig{
				Severity: config.SeverityInfo,
			},
			want: ExitCodeCritical,
		},
		{
			name: "high",
			sum: summary{
				count: map[config.Severity]int{
					config.SeverityCritical: 0,
					config.SeverityHigh:     1,
					config.SeverityMedium:   1,
					config.SeverityLow:      1,
					config.SeverityInfo:     1,
				},
			},
			status: []checkStatus{
				{
					Checktype: "Checktype1",
					Target:    "Target1",
					Status:    "FINISHED",
				},
			},
			rConfig: config.ReportConfig{
				Severity: config.SeverityInfo,
			},
			want: ExitCodeHigh,
		},
		{
			name: "medium",
			sum: summary{
				count: map[config.Severity]int{
					config.SeverityCritical: 0,
					config.SeverityHigh:     0,
					config.SeverityMedium:   1,
					config.SeverityLow:      1,
					config.SeverityInfo:     1,
				},
			},
			status: []checkStatus{
				{
					Checktype: "Checktype1",
					Target:    "Target1",
					Status:    "FINISHED",
				},
			},
			rConfig: config.ReportConfig{
				Severity: config.SeverityInfo,
			},
			want: ExitCodeMedium,
		},
		{
			name: "low",
			sum: summary{
				count: map[config.Severity]int{
					config.SeverityCritical: 0,
					config.SeverityHigh:     0,
					config.SeverityMedium:   0,
					config.SeverityLow:      1,
					config.SeverityInfo:     1,
				},
			},
			status: []checkStatus{
				{
					Checktype: "Checktype1",
					Target:    "Target1",
					Status:    "FINISHED",
				},
			},
			rConfig: config.ReportConfig{
				Severity: config.SeverityInfo,
			},
			want: ExitCodeLow,
		},
		{
			name: "info",
			sum: summary{
				count: map[config.Severity]int{
					config.SeverityCritical: 0,
					config.SeverityHigh:     0,
					config.SeverityMedium:   0,
					config.SeverityLow:      0,
					config.SeverityInfo:     1,
				},
			},
			status: []checkStatus{
				{
					Checktype: "Checktype1",
					Target:    "Target1",
					Status:    "FINISHED",
				},
			},
			rConfig: config.ReportConfig{
				Severity: config.SeverityInfo,
			},
			want: ExitCodeInfo,
		},
		{
			name: "zero exit code",
			sum: summary{
				count: map[config.Severity]int{
					config.SeverityCritical: 0,
					config.SeverityHigh:     0,
					config.SeverityMedium:   1,
					config.SeverityLow:      1,
					config.SeverityInfo:     1,
				},
			},
			status: []checkStatus{
				{
					Checktype: "Checktype1",
					Target:    "Target1",
					Status:    "FINISHED",
				},
			},

			rConfig: config.ReportConfig{
				Severity: config.SeverityHigh,
			},
			want: 0,
		},
		{
			name: "failed check",
			sum: summary{
				count: map[config.Severity]int{
					config.SeverityCritical: 0,
					config.SeverityHigh:     0,
					config.SeverityMedium:   1,
					config.SeverityLow:      1,
					config.SeverityInfo:     1,
				},
			},
			status: []checkStatus{
				{
					Checktype: "Checktype1",
					Target:    "Target1",
					Status:    "FAILED",
				},
			},
			rConfig: config.ReportConfig{
				Severity: config.SeverityHigh,
			},
			want: ExitCodeCheckError,
		},
		{
			name: "inconclusive check",
			sum: summary{
				count: map[config.Severity]int{
					config.SeverityCritical: 0,
					config.SeverityHigh:     0,
					config.SeverityMedium:   1,
					config.SeverityLow:      1,
					config.SeverityInfo:     1,
				},
			},
			status: []checkStatus{
				{
					Checktype: "Checktype1",
					Target:    "Target1",
					Status:    "INCONCLUSIVE",
				},
			},
			rConfig: config.ReportConfig{
				Severity: config.SeverityHigh,
			},
			want: ExitCodeCheckError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, err := NewWriter(tt.rConfig)
			if err != nil {
				t.Fatalf("unable to create a report writer: %v", err)
			}
			got := w.calculateExitCode(tt.sum, tt.status)
			if got != tt.want {
				t.Errorf("unexpected exit code: got: %v, want: %v", got, tt.want)
			}
		})
	}
}

func TestScoreToSeverity(t *testing.T) {
	tests := []struct {
		name  string
		score float32
		want  config.Severity
	}{
		{
			name:  "critical",
			score: 9,
			want:  config.SeverityCritical,
		},
		{
			name:  "high",
			score: 7,
			want:  config.SeverityHigh,
		},
		{
			name:  "medium",
			score: 4,
			want:  config.SeverityMedium,
		},
		{
			name:  "low",
			score: 0.1,
			want:  config.SeverityLow,
		},
		{
			name:  "info",
			score: 0,
			want:  config.SeverityInfo,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scoreToSeverity(tt.score)
			if got != tt.want {
				t.Errorf("unexpected severity: got: %v, want: %v", got, tt.want)
			}
		})
	}
}

func TestWriter_parseReport(t *testing.T) {
	tests := []struct {
		name       string
		report     engine.Report
		rConfig    config.ReportConfig
		want       []vulnerability
		wantNilErr bool
	}{
		{
			name: "all vulnerabilities included",
			report: map[string]vreport.Report{
				"CheckID1": {
					CheckData: vreport.CheckData{
						CheckID: "CheckID1",
					},
					ResultData: vreport.ResultData{
						Vulnerabilities: []vreport.Vulnerability{
							{
								Summary: "Vulnerability Summary 1",
							},
						},
					},
				},
				"CheckID2": {
					CheckData: vreport.CheckData{
						CheckID: "CheckID2",
					},
					ResultData: vreport.ResultData{
						Vulnerabilities: []vreport.Vulnerability{
							{
								Summary: "Vulnerability Summary 2",
								Score:   6.7,
							},
						},
					},
				},
			},
			rConfig: config.ReportConfig{
				Exclusions: []config.Exclusion{},
			},
			want: []vulnerability{
				{
					CheckData: vreport.CheckData{
						CheckID: "CheckID1",
					},
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 1",
					},
					Severity: config.SeverityInfo,
					excluded: false,
				},
				{
					CheckData: vreport.CheckData{
						CheckID: "CheckID2",
					},
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 2",
						Score:   6.7,
					},
					Severity: config.SeverityMedium,
					excluded: false,
				},
			},
			wantNilErr: true,
		},
		{
			name: "some vulnerabilities excluded",
			report: map[string]vreport.Report{
				"CheckID1": {
					CheckData: vreport.CheckData{
						CheckID: "CheckID1",
					},
					ResultData: vreport.ResultData{
						Vulnerabilities: []vreport.Vulnerability{
							{
								Summary: "Vulnerability Summary 1",
							},
						},
					},
				},
				"CheckID2": {
					CheckData: vreport.CheckData{
						CheckID: "CheckID2",
					},
					ResultData: vreport.ResultData{
						Vulnerabilities: []vreport.Vulnerability{
							{
								Summary: "Vulnerability Summary 2",
								Score:   6.7,
							},
						},
					},
				},
			},
			rConfig: config.ReportConfig{
				Exclusions: []config.Exclusion{
					{Summary: "Summary 2"},
				},
			},
			want: []vulnerability{
				{
					CheckData: vreport.CheckData{
						CheckID: "CheckID1",
					},
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 1",
					},
					Severity: config.SeverityInfo,
					excluded: false,
				},
				{
					CheckData: vreport.CheckData{
						CheckID: "CheckID2",
					},
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 2",
						Score:   6.7,
					},
					Severity: config.SeverityMedium,
					excluded: true,
				},
			},
			wantNilErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, err := NewWriter(tt.rConfig)
			if err != nil {
				t.Fatalf("unable to create a report writer: %v", err)
			}
			got, err := w.parseReport(tt.report)
			if (err == nil) != tt.wantNilErr {
				t.Errorf("unexpected error value: %v", err)
			}
			diffOpts := []cmp.Option{
				cmp.AllowUnexported(vulnerability{}),
				cmpopts.SortSlices(vulnLess),
			}
			if diff := cmp.Diff(tt.want, got, diffOpts...); diff != "" {
				t.Errorf("vulnerabilities mismatch (-want +got):\n%v", diff)
			}
		})
	}
}

func TestWriter_isExcluded(t *testing.T) {
	tests := []struct {
		name          string
		vulnerability vreport.Vulnerability
		target        string
		rConfig       config.ReportConfig
		want          bool
		wantNilErr    bool
	}{
		{
			name: "empty exclusions",
			vulnerability: vreport.Vulnerability{
				Summary: "Vulnerability Summary 1",
				Score:   6.7,
			},
			target: ".",
			rConfig: config.ReportConfig{
				Exclusions: []config.Exclusion{},
			},
			want:       false,
			wantNilErr: true,
		},
		{
			name: "exclude by summary",
			vulnerability: vreport.Vulnerability{
				Summary: "Vulnerability Summary 1",
				Score:   6.7,
			},
			target: ".",
			rConfig: config.ReportConfig{
				Exclusions: []config.Exclusion{
					{
						Summary:     "Summary 1",
						Description: "Excluded vulnerabilities Summary 1",
					},
				},
			},
			want:       true,
			wantNilErr: true,
		},
		{
			name: "not exclude by summary",
			vulnerability: vreport.Vulnerability{
				Summary: "Vulnerability Summary 1",
				Score:   6.7,
			},
			target: ".",
			rConfig: config.ReportConfig{
				Exclusions: []config.Exclusion{
					{
						Summary:     "Summary 2",
						Description: "Excluded vulnerabilities Summary 2",
					},
				},
			},
			want:       false,
			wantNilErr: true,
		},
		{
			name: "exclude by fingerprint",
			vulnerability: vreport.Vulnerability{
				Summary:     "Vulnerability Summary 1",
				Score:       6.7,
				Fingerprint: "12345",
			},
			target: ".",
			rConfig: config.ReportConfig{
				Exclusions: []config.Exclusion{
					{
						Fingerprint: "12345",
					},
				},
			},
			want:       true,
			wantNilErr: true,
		},
		{
			name: "exclude by affected resource",
			vulnerability: vreport.Vulnerability{
				Summary:          "Vulnerability Summary 1",
				Score:            6.7,
				AffectedResource: "Resource 1",
			},
			target: ".",
			rConfig: config.ReportConfig{
				Exclusions: []config.Exclusion{
					{
						Resource: "Resource 1",
					},
				},
			},
			want:       true,
			wantNilErr: true,
		},
		{
			name: "exclude by affected resource string",
			vulnerability: vreport.Vulnerability{
				Summary:                "Vulnerability Summary 1",
				Score:                  6.7,
				AffectedResourceString: "Resource String 1",
			},
			target: ".",
			rConfig: config.ReportConfig{
				Exclusions: []config.Exclusion{
					{
						Resource: "Resource String 1",
					},
				},
			},
			want:       true,
			wantNilErr: true,
		},
		{
			name: "exclude by target",
			vulnerability: vreport.Vulnerability{
				Summary: "Vulnerability Summary 1",
				Score:   6.7,
			},
			target: ".",
			rConfig: config.ReportConfig{
				Exclusions: []config.Exclusion{
					{
						Target: ".",
					},
				},
			},
			want:       true,
			wantNilErr: true,
		},
		{
			name: "match all exclusion criteria (resource)",
			vulnerability: vreport.Vulnerability{
				Summary:          "Vulnerability Summary 1",
				Score:            6.7,
				AffectedResource: "Resource 1",
				Fingerprint:      "12345",
			},
			target: ".",
			rConfig: config.ReportConfig{
				Exclusions: []config.Exclusion{
					{
						Summary:     "Summary 1",
						Resource:    "Resource 1",
						Fingerprint: "12345",
						Target:      ".",
					},
				},
			},
			want:       true,
			wantNilErr: true,
		},
		{
			name: "match all exclusion criteria (resource string)",
			vulnerability: vreport.Vulnerability{
				Summary:                "Vulnerability Summary 1",
				Score:                  6.7,
				AffectedResourceString: "Resource String 1",
				Fingerprint:            "12345",
			},
			target: ".",
			rConfig: config.ReportConfig{
				Exclusions: []config.Exclusion{
					{
						Summary:     "Summary 1",
						Resource:    "Resource String 1",
						Fingerprint: "12345",
						Target:      ".",
					},
				},
			},
			want:       true,
			wantNilErr: true,
		},
		{
			name: "match all exclusion criteria (resource and resource string)",
			vulnerability: vreport.Vulnerability{
				Summary:                "Vulnerability Summary 1",
				Score:                  6.7,
				AffectedResource:       "Resource 1",
				AffectedResourceString: "Resource String 1",
				Fingerprint:            "12345",
			},
			target: ".",
			rConfig: config.ReportConfig{
				Exclusions: []config.Exclusion{
					{
						Summary:     "Summary 1",
						Resource:    "Resource",
						Fingerprint: "12345",
						Target:      ".",
					},
				},
			},
			want:       true,
			wantNilErr: true,
		},
		{
			name: "fail an exclusion criteria",
			vulnerability: vreport.Vulnerability{
				Summary:                "Vulnerability Summary 1",
				Score:                  6.7,
				AffectedResource:       "Resource 1",
				AffectedResourceString: "Resource String 1",
				Fingerprint:            "12345",
			},
			target: ".",
			rConfig: config.ReportConfig{
				Exclusions: []config.Exclusion{
					{
						Summary:     "Summary 1",
						Resource:    "not found",
						Fingerprint: "12345",
						Target:      ".",
					},
				},
			},
			want:       false,
			wantNilErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, err := NewWriter(tt.rConfig)
			if err != nil {
				t.Fatalf("unable to create a report writer: %v", err)
			}
			got, err := w.isExcluded(tt.vulnerability, tt.target)
			if (err == nil) != tt.wantNilErr {
				t.Errorf("unexpected error value: %v", err)
			}
			if got != tt.want {
				t.Errorf("unexpected excluded value: got: %v, want: %v", got, tt.want)
			}
		})
	}
}

func TestMkSummary(t *testing.T) {
	tests := []struct {
		name            string
		vulnerabilities []vulnerability
		want            summary
		wantNilErr      bool
	}{
		{
			name: "happy path",
			vulnerabilities: []vulnerability{
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 1",
					},
					Severity: config.SeverityCritical,
					excluded: false,
				},
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 2",
					},
					Severity: config.SeverityCritical,
					excluded: true,
				},
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 3",
					},
					Severity: config.SeverityHigh,
					excluded: false,
				},
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 4",
					},
					Severity: config.SeverityHigh,
					excluded: true,
				},
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 5",
					},
					Severity: config.SeverityMedium,
					excluded: false,
				},
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 6",
					},
					Severity: config.SeverityMedium,
					excluded: true,
				},
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 7",
					},
					Severity: config.SeverityLow,
					excluded: false,
				},
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 8",
					},
					Severity: config.SeverityLow,
					excluded: true,
				},
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 9",
					},
					Severity: config.SeverityInfo,
					excluded: false,
				},
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 10",
					},
					Severity: config.SeverityInfo,
					excluded: true,
				},
			},
			want: summary{
				count: map[config.Severity]int{
					config.SeverityCritical: 1,
					config.SeverityHigh:     1,
					config.SeverityMedium:   1,
					config.SeverityLow:      1,
					config.SeverityInfo:     1,
				},
				excluded: 5,
			},
			wantNilErr: true,
		},
		{
			name: "unknown severity",
			vulnerabilities: []vulnerability{
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 1",
					},
					Severity: 7,
					excluded: false,
				},
			},
			want: summary{
				count:    nil,
				excluded: 0,
			},
			wantNilErr: false,
		},
		{
			name:            "empty summary",
			vulnerabilities: []vulnerability{},
			want: summary{
				count:    nil,
				excluded: 0,
			},
			wantNilErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := mkSummary(tt.vulnerabilities)
			if (err == nil) != tt.wantNilErr {
				t.Errorf("unexpected error value: %v", err)
			}
			if diff := cmp.Diff(tt.want, got, cmp.AllowUnexported(summary{})); diff != "" {
				t.Errorf("summary mismatch (-want +got):\n%v", diff)
			}
		})
	}
}

func TestMkStatus(t *testing.T) {
	tests := []struct {
		name string
		er   engine.Report
		want []checkStatus
	}{
		{
			name: "multiple checks",
			er: engine.Report{
				"CheckID1": vreport.Report{
					CheckData: vreport.CheckData{
						ChecktypeName: "Checktype1",
						Target:        "Target1",
						Status:        "Status1",
					},
				},
				"CheckID2": vreport.Report{
					CheckData: vreport.CheckData{
						ChecktypeName: "Checktype2",
						Target:        "Target2",
						Status:        "Status2",
					},
				},
			},
			want: []checkStatus{
				{
					Checktype: "Checktype1",
					Target:    "Target1",
					Status:    "Status1",
				},
				{
					Checktype: "Checktype2",
					Target:    "Target2",
					Status:    "Status2",
				},
			},
		},
		{
			name: "duplicated check",
			er: engine.Report{
				"CheckID1": vreport.Report{
					CheckData: vreport.CheckData{
						ChecktypeName: "Checktype1",
						Target:        "Target1",
						Status:        "Status1",
					},
				},
				"CheckID2": vreport.Report{
					CheckData: vreport.CheckData{
						ChecktypeName: "Checktype1",
						Target:        "Target1",
						Status:        "Status1",
					},
				},
			},
			want: []checkStatus{
				{
					Checktype: "Checktype1",
					Target:    "Target1",
					Status:    "Status1",
				},
				{
					Checktype: "Checktype1",
					Target:    "Target1",
					Status:    "Status1",
				},
			},
		},
		{
			name: "empty",
			er:   engine.Report{},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mkStatus(tt.er)
			if diff := cmp.Diff(tt.want, got, cmpopts.SortSlices(statusLess)); diff != "" {
				t.Errorf("status mismatch (-want +got):\n%v", diff)
			}
		})
	}
}

func TestWriter_filterVulns(t *testing.T) {
	tests := []struct {
		name            string
		vulnerabilities []vulnerability
		rConfig         config.ReportConfig
		want            []vulnerability
	}{
		{
			name: "filter excluded",
			vulnerabilities: []vulnerability{
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 1",
					},
					Severity: config.SeverityCritical,
					excluded: false,
				},
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 2",
					},
					Severity: config.SeverityCritical,
					excluded: true,
				},
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 3",
					},
					Severity: config.SeverityHigh,
					excluded: false,
				},
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 4",
					},
					Severity: config.SeverityHigh,
					excluded: true,
				},
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 5",
					},
					Severity: config.SeverityMedium,
					excluded: false,
				},
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 6",
					},
					Severity: config.SeverityMedium,
					excluded: true,
				},
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 7",
					},
					Severity: config.SeverityLow,
					excluded: false,
				},
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 8",
					},
					Severity: config.SeverityLow,
					excluded: true,
				},
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 9",
					},
					Severity: config.SeverityInfo,
					excluded: false,
				},
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 10",
					},
					Severity: config.SeverityInfo,
					excluded: true,
				},
			},
			rConfig: config.ReportConfig{
				Severity: config.SeverityInfo,
			},
			want: []vulnerability{
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 1",
					},
					Severity: config.SeverityCritical,
					excluded: false,
				},
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 3",
					},
					Severity: config.SeverityHigh,
					excluded: false,
				},
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 5",
					},
					Severity: config.SeverityMedium,
					excluded: false,
				},
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 7",
					},
					Severity: config.SeverityLow,
					excluded: false,
				},
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 9",
					},
					Severity: config.SeverityInfo,
					excluded: false,
				},
			},
		},
		{
			name: "filter excluded and lower than high",
			vulnerabilities: []vulnerability{
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 1",
					},
					Severity: config.SeverityCritical,
					excluded: false,
				},
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 2",
					},
					Severity: config.SeverityCritical,
					excluded: true,
				},
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 3",
					},
					Severity: config.SeverityHigh,
					excluded: false,
				},
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 4",
					},
					Severity: config.SeverityHigh,
					excluded: true,
				},
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 5",
					},
					Severity: config.SeverityMedium,
					excluded: false,
				},
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 6",
					},
					Severity: config.SeverityMedium,
					excluded: true,
				},
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 7",
					},
					Severity: config.SeverityLow,
					excluded: false,
				},
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 8",
					},
					Severity: config.SeverityLow,
					excluded: true,
				},
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 9",
					},
					Severity: config.SeverityInfo,
					excluded: false,
				},
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 10",
					},
					Severity: config.SeverityInfo,
					excluded: true,
				},
			},
			rConfig: config.ReportConfig{
				Severity: config.SeverityHigh,
			},
			want: []vulnerability{
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 1",
					},
					Severity: config.SeverityCritical,
					excluded: false,
				},
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 3",
					},
					Severity: config.SeverityHigh,
					excluded: false,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, err := NewWriter(tt.rConfig)
			if err != nil {
				t.Fatalf("unable to create a report writer: %v", err)
			}
			got := w.filterVulns(tt.vulnerabilities)
			if diff := cmp.Diff(tt.want, got, cmp.AllowUnexported(vulnerability{})); diff != "" {
				t.Errorf("summary mismatch (-want +got):\n%v", diff)
			}
		})
	}
}

func TestNewWriter_OutputFile(t *testing.T) {
	tests := []struct {
		name         string
		report       engine.Report
		rConfig      config.ReportConfig
		wantExitCode ExitCode
		wantNilErr   bool
	}{
		{
			name: "Standard Output JSON Report",
			report: map[string]vreport.Report{
				"CheckID1": {
					CheckData: vreport.CheckData{
						CheckID:       "CheckID1",
						ChecktypeName: "Checktype1",
						Target:        "Target1",
						Status:        "FINISHED",
					},
					ResultData: vreport.ResultData{
						Vulnerabilities: []vreport.Vulnerability{
							{
								Summary: "Vulnerability Summary 1",
								Description: "Lorem ipsum dolor sit amet, " +
									"consectetur adipiscing elit. Nam malesuada " +
									"pretium ligula, ac egestas leo egestas nec. " +
									"Morbi id placerat ipsum. Donec semper enim urna, " +
									"et bibendum ex dictum in. Quisque venenatis " +
									"in sem in lacinia. Fusce lacus odio, molestie " +
									"vitae mi nec, elementum pellentesque augue. " +
									"Aenean imperdiet odio eu sodales molestie. " +
									"Fusce ut elementum leo. Nam sodales molestie " +
									"lorem in rutrum. Pellentesque nec sapien elit. " +
									"Sed tincidunt ut augue sit amet cursus. " +
									"In convallis magna sit amet tempus pellentesque. " +
									"Nam commodo porttitor ante sed volutpat. " +
									"Ut vulputate leo quis ultricies sodales.",
								AffectedResource: "Affected Resource 1",
								ImpactDetails:    "Impact detail 1",
								Recommendations: []string{
									"Recommendation 1",
									"Recommendation 2",
									"Recommendation 3",
								},
								Details: "Vulnerability Detail 1",
								References: []string{
									"Reference 1",
									"Reference 2",
									"Reference 3",
								},
								Resources: []vreport.ResourcesGroup{
									{
										Name: "Resource 1",
										Header: []string{
											"Header 1",
											"Header 2",
											"Header 3",
											"Header 4",
										},
										Rows: []map[string]string{
											{
												"Header 1": "row 11",
												"Header 2": "row 12",
												"Header 3": "row 13",
												"Header 4": "row 14",
											},
											{
												"Header 1": "row 21",
												"Header 2": "row 22",
												"Header 3": "row 23",
												"Header 4": "row 24",
											},
											{
												"Header 1": "row 31",
												"Header 2": "row 32",
												"Header 3": "row 33",
												"Header 4": "row 34",
											},
											{
												"Header 1": "row 41",
												"Header 2": "row 42",
												"Header 3": "row 43",
												"Header 4": "row 44",
											},
										},
									},
									{
										Name: "Resource 2",
										Header: []string{
											"Header 1",
											"Header 2",
										},
										Rows: []map[string]string{
											{
												"Header 1": "row 11",
												"Header 2": "row 12",
											},
											{
												"Header 1": "row 21",
												"Header 2": "row 22",
											},
										},
									},
									{
										Name: "Resource 3",
										Header: []string{
											"Header 1",
											"Header 2",
										},
										Rows: []map[string]string{
											{
												"Header 1": "row 11",
												"Header 2": "row 12",
											},
											{
												"Header 1": "row 21",
												"Header 2": "row 22",
											},
										},
									},
									{
										Name: "Resource 4",
										Header: []string{
											"Header 1",
											"Header 2",
										},
										Rows: []map[string]string{
											{
												"Header 1": "row 11",
												"Header 2": "row 12",
											},
											{
												"Header 1": "row 21",
												"Header 2": "row 22",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			rConfig: config.ReportConfig{
				Severity:   config.SeverityInfo,
				OutputFile: "test.json",
				Format:     config.OutputFormatJSON,
			},
			wantExitCode: ExitCodeInfo,
			wantNilErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpPath, err := os.MkdirTemp("", "")
			if err != nil {
				t.Fatalf("unable to create a temporary dir")
			}
			defer os.RemoveAll(tmpPath)

			tt.rConfig.OutputFile = path.Join(tmpPath, tt.rConfig.OutputFile)
			writer, err := NewWriter(tt.rConfig)
			if err != nil {
				t.Fatalf("unable to create a report writer: %v", err)
			}
			defer writer.Close()
			gotExitCode, err := writer.Write(tt.report)
			if (err == nil) != tt.wantNilErr {
				t.Errorf("unexpected error value: %v", err)
			}
			if gotExitCode != tt.wantExitCode {
				t.Errorf("unexpected error value: got: %d, want: %d", gotExitCode, tt.wantExitCode)
			}

			if _, err = os.Stat(tt.rConfig.OutputFile); err != nil {
				t.Fatalf("unexpected error value: %v", err)
			}
		})
	}
}

func vulnLess(a, b vulnerability) bool {
	h := func(v vulnerability) string {
		return fmt.Sprintf("%#v", v)
	}
	return h(a) < h(b)
}

func statusLess(a, b checkStatus) bool {
	h := func(v checkStatus) string {
		return fmt.Sprintf("%#v", v)
	}
	return h(a) < h(b)
}
