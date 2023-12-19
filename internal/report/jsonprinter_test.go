// Copyright 2023 Adevinta

package report

import (
	"bytes"
	"encoding/json"
	"testing"

	vreport "github.com/adevinta/vulcan-report"
	"github.com/google/go-cmp/cmp"
)

func TestJsonPrinter_Print(t *testing.T) {
	tests := []struct {
		name            string
		vulnerabilities []vulnerability
		wantNilErr      bool
	}{
		{
			name: "Standard Output JSON Report",
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
					},
				},
			},
			wantNilErr: true,
		},
		{
			name: "No vulnerabilities",
			vulnerabilities: []vulnerability{
				{
					Vulnerability: vreport.Vulnerability{},
					CheckData: vreport.CheckData{
						CheckID: "CheckID1",
					},
				},
			},
			wantNilErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := jsonPrinter{}
			err := w.Print(&buf, tt.vulnerabilities, summary{}, nil)
			if (err == nil) != tt.wantNilErr {
				t.Errorf("unexpected error value: %v", err)
			}

			var got []vulnerability
			if err = json.Unmarshal(buf.Bytes(), &got); err != nil {
				t.Errorf("unmarshal json report: %v", err)
			}
			diffOpts := []cmp.Option{
				cmp.AllowUnexported(vulnerability{}),
			}
			if diff := cmp.Diff(tt.vulnerabilities, got, diffOpts...); diff != "" {
				t.Errorf("vulnerabilities mismatch (-want +got):\n%v", diff)
			}
		})
	}
}
