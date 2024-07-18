// Copyright 2023 Adevinta

package report

import (
	"bytes"
	"strings"
	"testing"

	vreport "github.com/adevinta/vulcan-report"

	"github.com/adevinta/lava/internal/config"
)

func TestUserFriendlyPrinter_Print(t *testing.T) {
	tests := []struct {
		name            string
		vulnerabilities []vulnerability
		summ            summary
		status          []checkStatus
		staleExcls      []config.Exclusion
		want            []string
	}{
		{
			name: "User Friendly Report",
			vulnerabilities: []vulnerability{
				{
					Vulnerability: vreport.Vulnerability{
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
					CheckData: vreport.CheckData{
						CheckID: "CheckID1",
						Target:  ".",
					},
				},
			},
			summ: summary{
				count: map[config.Severity]int{
					config.SeverityHigh:   3,
					config.SeverityMedium: 15,
				},
				excluded: 3,
			},
			status: []checkStatus{
				{
					Checktype: "Check1",
					Target:    ".",
					Status:    "FINISHED",
				},
			},
			staleExcls: []config.Exclusion{
				{Summary: "Unused exclusion"},
			},
			want: []string{
				"STATUS",
				"FINISHED",
				"SUMMARY",
				"Number of excluded vulnerabilities not included in the summary table: 3",
				"VULNERABILITIES",
				"Vulnerability Summary 1",
				"STALE EXCLUSIONS",
				"- Summary: Unused exclusion",
			},
		},
		{
			name:            "No vulnerabilities",
			vulnerabilities: nil,
			status: []checkStatus{
				{
					Checktype: "Check1",
					Target:    ".",
					Status:    "FINISHED",
				},
			},
			want: []string{
				"STATUS",
				"FINISHED",
				"SUMMARY",
				"No vulnerabilities found during the scan.",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := humanPrinter{}
			if err := w.Print(&buf, tt.vulnerabilities, tt.summ, tt.status, tt.staleExcls); err != nil {
				t.Errorf("unexpected error value: %v", err)
			}
			text := buf.String()

			for _, wantLine := range tt.want {
				if !strings.Contains(text, wantLine) {
					t.Errorf("text not found: %s", wantLine)
				}
			}
		})
	}
}
