// Copyright 2023 Adevinta

package report

import (
	"fmt"
	"os"
	"path"
	"testing"
	"time"

	vreport "github.com/adevinta/vulcan-report"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/adevinta/lava/internal/config"
	"github.com/adevinta/lava/internal/engine"
)

func TestWriter_calculateExitCode(t *testing.T) {
	tests := []struct {
		name   string
		summ   summary
		status []checkStatus
		cfg    WriterConfig
		want   ExitCode
	}{
		{
			name: "critical",
			summ: summary{
				Count: map[config.Severity]int{
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
			cfg: WriterConfig{
				ReportConfig: config.ReportConfig{
					Severity: config.SeverityInfo,
				},
			},
			want: ExitCodeCritical,
		},
		{
			name: "high",
			summ: summary{
				Count: map[config.Severity]int{
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
			cfg: WriterConfig{
				ReportConfig: config.ReportConfig{
					Severity: config.SeverityInfo,
				},
			},
			want: ExitCodeHigh,
		},
		{
			name: "medium",
			summ: summary{
				Count: map[config.Severity]int{
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
			cfg: WriterConfig{
				ReportConfig: config.ReportConfig{
					Severity: config.SeverityInfo,
				},
			},
			want: ExitCodeMedium,
		},
		{
			name: "low",
			summ: summary{
				Count: map[config.Severity]int{
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
			cfg: WriterConfig{
				ReportConfig: config.ReportConfig{
					Severity: config.SeverityInfo,
				},
			},
			want: ExitCodeLow,
		},
		{
			name: "info",
			summ: summary{
				Count: map[config.Severity]int{
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
			cfg: WriterConfig{
				ReportConfig: config.ReportConfig{
					Severity: config.SeverityInfo,
				},
			},
			want: ExitCodeInfo,
		},
		{
			name: "zero exit code",
			summ: summary{
				Count: map[config.Severity]int{
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

			cfg: WriterConfig{
				ReportConfig: config.ReportConfig{
					Severity: config.SeverityHigh,
				},
			},
			want: 0,
		},
		{
			name: "failed check",
			summ: summary{
				Count: map[config.Severity]int{
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
			cfg: WriterConfig{
				ReportConfig: config.ReportConfig{
					Severity: config.SeverityHigh,
				},
			},
			want: ExitCodeCheckError,
		},
		{
			name: "inconclusive check",
			summ: summary{
				Count: map[config.Severity]int{
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
			cfg: WriterConfig{
				ReportConfig: config.ReportConfig{
					Severity: config.SeverityHigh,
				},
			},
			want: ExitCodeCheckError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, err := NewWriter(tt.cfg)
			if err != nil {
				t.Fatalf("unable to create a report writer: %v", err)
			}
			got := w.calculateExitCode(tt.summ, tt.status)
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
		cfg        WriterConfig
		want       []metaVuln
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
			cfg: WriterConfig{
				ReportConfig: config.ReportConfig{
					Exclusions:   []config.Exclusion{},
					ShowSeverity: ptr(config.SeverityMedium),
				},
			},
			want: []metaVuln{
				{
					repVuln: repVuln{
						CheckData: vreport.CheckData{
							CheckID: "CheckID1",
						},
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 1",
						},
						Severity: config.SeverityInfo,
					},
					Shown:    false,
					Excluded: false,
				},
				{
					repVuln: repVuln{
						CheckData: vreport.CheckData{
							CheckID: "CheckID2",
						},
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 2",
							Score:   6.7,
						},
						Severity: config.SeverityMedium,
					},
					Shown:    true,
					Excluded: false,
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
			cfg: WriterConfig{
				ReportConfig: config.ReportConfig{
					Exclusions: []config.Exclusion{
						{Summary: "Summary 2"},
					},
					ShowSeverity: ptr(config.SeverityMedium),
				},
			},
			want: []metaVuln{
				{
					repVuln: repVuln{
						CheckData: vreport.CheckData{
							CheckID: "CheckID1",
						},
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 1",
						},
						Severity: config.SeverityInfo,
					},
					Shown:    false,
					Excluded: false,
				},
				{
					repVuln: repVuln{
						CheckData: vreport.CheckData{
							CheckID: "CheckID2",
						},
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 2",
							Score:   6.7,
						},
						Severity: config.SeverityMedium,
					},
					Shown:    false,
					Excluded: true,
					ExclusionRule: &config.Exclusion{
						Summary: "Summary 2",
					},
				},
			},
			wantNilErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, err := NewWriter(tt.cfg)
			if err != nil {
				t.Fatalf("unable to create a report writer: %v", err)
			}
			got, err := w.parseReport(tt.report)
			if (err == nil) != tt.wantNilErr {
				t.Errorf("unexpected error value: %v", err)
			}
			diffOpts := []cmp.Option{
				cmp.AllowUnexported(metaVuln{}),
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
		cfg           WriterConfig
		want          bool
		wantRule      int
		wantNilErr    bool
	}{
		{
			name: "empty exclusions",
			vulnerability: vreport.Vulnerability{
				Summary: "Vulnerability Summary 1",
				Score:   6.7,
			},
			target: ".",
			cfg: WriterConfig{
				ReportConfig: config.ReportConfig{
					Exclusions: []config.Exclusion{},
				},
			},
			want:       false,
			wantRule:   0,
			wantNilErr: true,
		},
		{
			name: "exclude by summary",
			vulnerability: vreport.Vulnerability{
				Summary: "Vulnerability Summary 1",
				Score:   6.7,
			},
			target: ".",
			cfg: WriterConfig{
				ReportConfig: config.ReportConfig{
					Exclusions: []config.Exclusion{
						{
							Summary:     "Summary 0",
							Description: "Excluded vulnerabilities Summary 0",
						},
						{
							Summary:     "Summary 1",
							Description: "Excluded vulnerabilities Summary 1",
						},
					},
				},
			},
			want:       true,
			wantRule:   1,
			wantNilErr: true,
		},
		{
			name: "not exclude by summary",
			vulnerability: vreport.Vulnerability{
				Summary: "Vulnerability Summary 1",
				Score:   6.7,
			},
			target: ".",
			cfg: WriterConfig{
				ReportConfig: config.ReportConfig{
					Exclusions: []config.Exclusion{
						{
							Summary:     "Summary 2",
							Description: "Excluded vulnerabilities Summary 2",
						},
					},
				},
			},
			want:       false,
			wantRule:   0,
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
			cfg: WriterConfig{
				ReportConfig: config.ReportConfig{
					Exclusions: []config.Exclusion{
						{
							Fingerprint: "0000",
						},
						{
							Fingerprint: "12345",
						},
					},
				},
			},
			want:       true,
			wantRule:   1,
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
			cfg: WriterConfig{
				ReportConfig: config.ReportConfig{
					Exclusions: []config.Exclusion{
						{
							Resource: "Resource 0",
						},
						{
							Resource: "Resource 1",
						},
					},
				},
			},
			want:       true,
			wantRule:   1,
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
			cfg: WriterConfig{
				ReportConfig: config.ReportConfig{
					Exclusions: []config.Exclusion{
						{
							Resource: "Resource String 0",
						},
						{
							Resource: "Resource String 1",
						},
					},
				},
			},
			want:       true,
			wantRule:   1,
			wantNilErr: true,
		},
		{
			name: "exclude by target",
			vulnerability: vreport.Vulnerability{
				Summary: "Vulnerability Summary 1",
				Score:   6.7,
			},
			target: ".",
			cfg: WriterConfig{
				ReportConfig: config.ReportConfig{
					Exclusions: []config.Exclusion{
						{
							Target: "0",
						},
						{
							Target: ".",
						},
					},
				},
			},
			want:       true,
			wantRule:   1,
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
			cfg: WriterConfig{
				ReportConfig: config.ReportConfig{
					Exclusions: []config.Exclusion{
						{
							Summary:     "Summary 0",
							Resource:    "Resource 0",
							Fingerprint: "00000",
							Target:      "0",
						},
						{
							Summary:     "Summary 1",
							Resource:    "Resource 1",
							Fingerprint: "12345",
							Target:      ".",
						},
					},
				},
			},
			want:       true,
			wantRule:   1,
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
			cfg: WriterConfig{
				ReportConfig: config.ReportConfig{
					Exclusions: []config.Exclusion{
						{
							Summary:     "Summary 0",
							Resource:    "Resource String 0",
							Fingerprint: "00000",
							Target:      "0",
						},
						{
							Summary:     "Summary 1",
							Resource:    "Resource String 1",
							Fingerprint: "12345",
							Target:      ".",
						},
					},
				},
			},
			want:       true,
			wantRule:   1,
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
			cfg: WriterConfig{
				ReportConfig: config.ReportConfig{
					Exclusions: []config.Exclusion{
						{
							Summary:     "Summary 0",
							Resource:    "Resource 0",
							Fingerprint: "00000",
							Target:      "0",
						},
						{
							Summary:     "Summary 1",
							Resource:    "Resource 1",
							Fingerprint: "12345",
							Target:      ".",
						},
					},
				},
			},
			want:       true,
			wantRule:   1,
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
			cfg: WriterConfig{
				ReportConfig: config.ReportConfig{
					Exclusions: []config.Exclusion{
						{
							Summary:     "Summary 1",
							Resource:    "not found",
							Fingerprint: "12345",
							Target:      ".",
						},
					},
				},
			},
			want:       false,
			wantRule:   0,
			wantNilErr: true,
		},
		{
			name: "active exclusion",
			vulnerability: vreport.Vulnerability{
				Summary: "Vulnerability Summary 1",
				Score:   6.7,
			},
			target: ".",
			cfg: WriterConfig{
				ReportConfig: config.ReportConfig{
					Exclusions: []config.Exclusion{
						{
							Summary:        "Summary 1",
							Description:    "Excluded vulnerabilities Summary 1",
							ExpirationDate: ptr(mustParseExpDate("2024/05/06")),
						},
					},
				},
			},
			want:       true,
			wantRule:   0,
			wantNilErr: true,
		},
		{
			name: "expired exclusion",
			vulnerability: vreport.Vulnerability{
				Summary: "Vulnerability Summary 1",
				Score:   6.7,
			},
			target: ".",
			cfg: WriterConfig{
				ReportConfig: config.ReportConfig{
					Exclusions: []config.Exclusion{
						{
							Summary:        "Summary 1",
							Description:    "Excluded vulnerabilities Summary 1",
							ExpirationDate: ptr(mustParseExpDate("2023/05/06")),
						},
					},
				},
			},
			want:       false,
			wantRule:   0,
			wantNilErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldTimeNow := timeNow
			defer func() { timeNow = oldTimeNow }()
			timeNow = func() time.Time {
				tn, _ := time.Parse(time.RFC3339, "2024-01-02T15:04:05Z")
				return tn
			}

			w, err := NewWriter(tt.cfg)
			if err != nil {
				t.Fatalf("unable to create a report writer: %v", err)
			}
			got, gotRule, err := w.isExcluded(tt.vulnerability, tt.target)
			if (err == nil) != tt.wantNilErr {
				t.Errorf("unexpected error value: %v", err)
			}
			if got != tt.want {
				t.Errorf("unexpected excluded value: got: %v, want: %v", got, tt.want)
			}
			if gotRule != tt.wantRule {
				t.Errorf("unexpected rule: got: %v, want: %v", gotRule, tt.wantRule)
			}
		})
	}
}

func TestMkSummary(t *testing.T) {
	tests := []struct {
		name       string
		vulns      []metaVuln
		want       summary
		wantNilErr bool
	}{
		{
			name: "happy path",
			vulns: []metaVuln{
				{
					repVuln: repVuln{
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 1",
						},
						Severity: config.SeverityCritical,
					},
					Excluded: false,
				},
				{
					repVuln: repVuln{
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 2",
						},
						Severity: config.SeverityCritical,
					},
					Excluded: true,
				},
				{
					repVuln: repVuln{
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 3",
						},
						Severity: config.SeverityHigh,
					},
					Excluded: false,
				},
				{
					repVuln: repVuln{
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 4",
						},
						Severity: config.SeverityHigh,
					},
					Excluded: true,
				},
				{
					repVuln: repVuln{
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 5",
						},
						Severity: config.SeverityMedium,
					},
					Excluded: false,
				},
				{
					repVuln: repVuln{
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 6",
						},
						Severity: config.SeverityMedium,
					},
					Excluded: true,
				},
				{
					repVuln: repVuln{
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 7",
						},
						Severity: config.SeverityLow,
					},
					Excluded: false,
				},
				{
					repVuln: repVuln{
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 8",
						},
						Severity: config.SeverityLow,
					},
					Excluded: true,
				},
				{
					repVuln: repVuln{
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 9",
						},
						Severity: config.SeverityInfo,
					},
					Excluded: false,
				},
				{
					repVuln: repVuln{
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 10",
						},
						Severity: config.SeverityInfo,
					},
					Excluded: true,
				},
			},
			want: summary{
				Count: map[config.Severity]int{
					config.SeverityCritical: 1,
					config.SeverityHigh:     1,
					config.SeverityMedium:   1,
					config.SeverityLow:      1,
					config.SeverityInfo:     1,
				},
				Excluded: 5,
			},
			wantNilErr: true,
		},
		{
			name: "unknown severity",
			vulns: []metaVuln{
				{
					repVuln: repVuln{
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 1",
						},
						Severity: 7,
					},
					Excluded: false,
				},
			},
			want: summary{
				Count:    nil,
				Excluded: 0,
			},
			wantNilErr: false,
		},
		{
			name:  "empty summary",
			vulns: []metaVuln{},
			want: summary{
				Count:    nil,
				Excluded: 0,
			},
			wantNilErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := mkSummary(tt.vulns)
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
		name  string
		vulns []metaVuln
		cfg   WriterConfig
		want  []repVuln
	}{
		{
			name: "filter excluded",
			vulns: []metaVuln{
				{
					repVuln: repVuln{
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 1",
						},
						Severity: config.SeverityCritical,
					},
					Excluded: false,
				},
				{
					repVuln: repVuln{
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 2",
						},
						Severity: config.SeverityCritical,
					},
					Excluded: true,
				},
				{
					repVuln: repVuln{
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 3",
						},
						Severity: config.SeverityHigh,
					},
					Excluded: false,
				},
				{
					repVuln: repVuln{
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 4",
						},
						Severity: config.SeverityHigh,
					},
					Excluded: true,
				},
				{
					repVuln: repVuln{
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 5",
						},
						Severity: config.SeverityMedium,
					},
					Excluded: false,
				},
				{
					repVuln: repVuln{
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 6",
						},
						Severity: config.SeverityMedium,
					},
					Excluded: true,
				},
				{
					repVuln: repVuln{
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 7",
						},
						Severity: config.SeverityLow,
					},
					Excluded: false,
				},
				{
					repVuln: repVuln{
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 8",
						},
						Severity: config.SeverityLow,
					},
					Excluded: true,
				},
				{
					repVuln: repVuln{
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 9",
						},
						Severity: config.SeverityInfo,
					},
					Excluded: false,
				},
				{
					repVuln: repVuln{
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 10",
						},
						Severity: config.SeverityInfo,
					},
					Excluded: true,
				},
			},
			cfg: WriterConfig{
				ReportConfig: config.ReportConfig{
					Severity: config.SeverityInfo,
				},
			},
			want: []repVuln{
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 1",
					},
					Severity: config.SeverityCritical,
				},
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 3",
					},
					Severity: config.SeverityHigh,
				},
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 5",
					},
					Severity: config.SeverityMedium,
				},
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 7",
					},
					Severity: config.SeverityLow,
				},
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 9",
					},
					Severity: config.SeverityInfo,
				},
			},
		},
		{
			name: "filter excluded and lower than high",
			vulns: []metaVuln{
				{
					repVuln: repVuln{
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 1",
						},
						Severity: config.SeverityCritical,
					},
					Excluded: false,
				},
				{
					repVuln: repVuln{
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 2",
						},
						Severity: config.SeverityCritical,
					},
					Excluded: true,
				},
				{
					repVuln: repVuln{
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 3",
						},
						Severity: config.SeverityHigh,
					},
					Excluded: false,
				},
				{
					repVuln: repVuln{
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 4",
						},
						Severity: config.SeverityHigh,
					},
					Excluded: true,
				},
				{
					repVuln: repVuln{
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 5",
						},
						Severity: config.SeverityMedium,
					},
					Excluded: false,
				},
				{
					repVuln: repVuln{
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 6",
						},
						Severity: config.SeverityMedium,
					},
					Excluded: true,
				},
				{
					repVuln: repVuln{
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 7",
						},
						Severity: config.SeverityLow,
					},
					Excluded: false,
				},
				{
					repVuln: repVuln{
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 8",
						},
						Severity: config.SeverityLow,
					},
					Excluded: true,
				},
				{
					repVuln: repVuln{
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 9",
						},
						Severity: config.SeverityInfo,
					},
					Excluded: false,
				},
				{
					repVuln: repVuln{
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 10",
						},
						Severity: config.SeverityInfo,
					},
					Excluded: true,
				},
			},
			cfg: WriterConfig{
				ReportConfig: config.ReportConfig{
					Severity: config.SeverityHigh,
				},
			},
			want: []repVuln{
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 1",
					},
					Severity: config.SeverityCritical,
				},
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 3",
					},
					Severity: config.SeverityHigh,
				},
			},
		},
		{
			name: "show",
			vulns: []metaVuln{
				{
					repVuln: repVuln{
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 1",
						},
						Severity: config.SeverityCritical,
					},
				},
				{
					repVuln: repVuln{
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 2",
						},
						Severity: config.SeverityHigh,
					},
				},
				{
					repVuln: repVuln{
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 3",
						},
						Severity: config.SeverityMedium,
					},
				},
				{
					repVuln: repVuln{
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 4",
						},
						Severity: config.SeverityLow,
					},
				},
				{
					repVuln: repVuln{
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 5",
						},
						Severity: config.SeverityInfo,
					},
				},
			},
			cfg: WriterConfig{
				ReportConfig: config.ReportConfig{
					Severity:     config.SeverityCritical,
					ShowSeverity: ptr(config.SeverityMedium),
				},
			},
			want: []repVuln{
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 1",
					},
					Severity: config.SeverityCritical,
				},
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 2",
					},
					Severity: config.SeverityHigh,
				},
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 3",
					},
					Severity: config.SeverityMedium,
				},
			},
		},
		{
			name: "show higher than severity",
			vulns: []metaVuln{
				{
					repVuln: repVuln{
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 1",
						},
						Severity: config.SeverityCritical,
					},
				},
				{
					repVuln: repVuln{
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 2",
						},
						Severity: config.SeverityHigh,
					},
				},
				{
					repVuln: repVuln{
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 3",
						},
						Severity: config.SeverityMedium,
					},
				},
				{
					repVuln: repVuln{
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 4",
						},
						Severity: config.SeverityLow,
					},
				},
				{
					repVuln: repVuln{
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 5",
						},
						Severity: config.SeverityInfo,
					},
				},
			},
			cfg: WriterConfig{
				ReportConfig: config.ReportConfig{
					Severity:     config.SeverityMedium,
					ShowSeverity: ptr(config.SeverityHigh),
				},
			},
			want: []repVuln{
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 1",
					},
					Severity: config.SeverityCritical,
				},
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 2",
					},
					Severity: config.SeverityHigh,
				},
			},
		},
		{
			name: "default show",
			vulns: []metaVuln{
				{
					repVuln: repVuln{
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 1",
						},
						Severity: config.SeverityCritical,
					},
				},
				{
					repVuln: repVuln{
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 2",
						},
						Severity: config.SeverityHigh,
					},
				},
				{
					repVuln: repVuln{
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 3",
						},
						Severity: config.SeverityMedium,
					},
				},
				{
					repVuln: repVuln{
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 4",
						},
						Severity: config.SeverityLow,
					},
				},
				{
					repVuln: repVuln{
						Vulnerability: vreport.Vulnerability{
							Summary: "Vulnerability Summary 5",
						},
						Severity: config.SeverityInfo,
					},
				},
			},
			cfg: WriterConfig{
				ReportConfig: config.ReportConfig{
					Severity: config.SeverityHigh,
				},
			},
			want: []repVuln{
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 1",
					},
					Severity: config.SeverityCritical,
				},
				{
					Vulnerability: vreport.Vulnerability{
						Summary: "Vulnerability Summary 2",
					},
					Severity: config.SeverityHigh,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, err := NewWriter(tt.cfg)
			if err != nil {
				t.Fatalf("unable to create a report writer: %v", err)
			}
			got := w.filterVulns(tt.vulns)
			if diff := cmp.Diff(tt.want, got, cmp.AllowUnexported(metaVuln{})); diff != "" {
				t.Errorf("summary mismatch (-want +got):\n%v", diff)
			}
		})
	}
}

func TestNewWriter_OutputFile(t *testing.T) {
	report := map[string]vreport.Report{
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
	}

	tests := []struct {
		name         string
		cfg          WriterConfig
		wantExitCode ExitCode
	}{
		{
			name: "output file",
			cfg: WriterConfig{
				ReportConfig: config.ReportConfig{
					Severity:   config.SeverityInfo,
					OutputFile: "output.json",
					Format:     config.OutputFormatJSON,
				},
			},
			wantExitCode: ExitCodeInfo,
		},
		{
			name: "full report file",
			cfg: WriterConfig{
				ReportConfig: config.ReportConfig{
					Severity:   config.SeverityInfo,
					OutputFile: "output.json",
					Format:     config.OutputFormatJSON,
				},
				FullReportFile: "fullreport.json",
			},
			wantExitCode: ExitCodeInfo,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpPath, err := os.MkdirTemp("", "")
			if err != nil {
				t.Fatalf("unable to create a temporary dir")
			}
			defer os.RemoveAll(tmpPath)

			tt.cfg.ReportConfig.OutputFile = path.Join(tmpPath, tt.cfg.ReportConfig.OutputFile)
			if tt.cfg.FullReportFile != "" {
				tt.cfg.FullReportFile = path.Join(tmpPath, tt.cfg.FullReportFile)
			}

			writer, err := NewWriter(tt.cfg)
			if err != nil {
				t.Fatalf("unable to create a report writer: %v", err)
			}
			defer writer.Close()

			gotExitCode, err := writer.Write(report)
			if err != nil {
				t.Fatalf("unexpected write error: %v", err)
			}

			if _, err = os.Stat(tt.cfg.ReportConfig.OutputFile); err != nil {
				t.Errorf("could not stat output file: %v", err)
			}
			if tt.cfg.FullReportFile != "" {
				if _, err = os.Stat(tt.cfg.FullReportFile); err != nil {
					t.Errorf("could not stat full report file: %v", err)
				}
			}

			if gotExitCode != tt.wantExitCode {
				t.Errorf("unexpected exit code: got: %d, want: %d", gotExitCode, tt.wantExitCode)
			}
		})
	}
}

func vulnLess(a, b metaVuln) bool {
	h := func(v metaVuln) string {
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

func ptr[V any](v V) *V {
	return &v
}

func mustParseExpDate(date string) config.ExpirationDate {
	t, err := time.Parse(config.ExpirationDateLayout, date)
	if err != nil {
		panic(err)
	}
	return config.ExpirationDate{Time: t}
}
