// Copyright 2024 Adevinta

package config

import (
	"testing"

	types "github.com/adevinta/vulcan-types"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/adevinta/lava/internal/config/dag"
)

func TestNewConfigGraph(t *testing.T) {
	tests := []struct {
		name    string
		URL     string
		want    ConfigGraph
		wantErr bool
	}{
		{
			name: "no includes",
			URL:  "testdata/include/no_includes.yaml",
			want: ConfigGraph{
				configs: map[string]Config{
					"testdata/include/no_includes.yaml": {
						LavaVersion: ptr("v1.0.0"),
						ChecktypeURLs: []string{
							"checktypes_no_includes.json",
						},
						Targets: []Target{
							{
								Identifier: "example.com",
								AssetType:  types.DomainName,
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "local file",
			URL:  "testdata/include/local.yaml",
			want: ConfigGraph{
				configs: map[string]Config{
					"testdata/include/local.yaml": {
						Includes:    []string{"testdata/include/no_includes.yaml"},
						LavaVersion: ptr("v1.0.0"),
						ChecktypeURLs: []string{
							"checktypes_local.json",
						},
						Targets: []Target{
							{
								Identifier: "example.com",
								AssetType:  types.DomainName,
							},
						},
					},
					"testdata/include/no_includes.yaml": {
						LavaVersion: ptr("v1.0.0"),
						ChecktypeURLs: []string{
							"checktypes_no_includes.json",
						},
						Targets: []Target{
							{
								Identifier: "example.com",
								AssetType:  types.DomainName,
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name:    "autoinclude",
			URL:     "testdata/include/autoinclude.yaml",
			wantErr: true,
		},
		{
			name: "duplicated",
			URL:  "testdata/include/duplicated.yaml",
			want: ConfigGraph{
				configs: map[string]Config{
					"testdata/include/duplicated.yaml": {
						Includes: []string{
							"testdata/include/no_includes.yaml",
							"testdata/include/no_includes.yaml",
						},
						LavaVersion: ptr("v1.0.0"),
						ChecktypeURLs: []string{
							"checktypes.json",
						},
						Targets: []Target{
							{
								Identifier: "example.com",
								AssetType:  types.DomainName,
							},
						},
					},
					"testdata/include/no_includes.yaml": {
						LavaVersion: ptr("v1.0.0"),
						ChecktypeURLs: []string{
							"checktypes_no_includes.json",
						},
						Targets: []Target{
							{
								Identifier: "example.com",
								AssetType:  types.DomainName,
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "common includes",
			URL:  "testdata/include/common.yaml",
			want: ConfigGraph{
				configs: map[string]Config{
					"testdata/include/common.yaml": {
						Includes: []string{
							"testdata/include/common_a.yaml",
							"testdata/include/common_b.yaml",
						},
						LavaVersion: ptr("v1.0.0"),
						ChecktypeURLs: []string{
							"checktypes_common.json",
						},
						Targets: []Target{
							{
								Identifier: "example.com",
								AssetType:  types.DomainName,
							},
						},
						ReportConfig: ReportConfig{
							Severity: ptr(SeverityCritical),
						},
					},
					"testdata/include/common_a.yaml": {
						Includes:    []string{"testdata/include/no_includes.yaml"},
						LavaVersion: ptr("v1.0.0"),
						ChecktypeURLs: []string{
							"checktypes_a.json",
						},
						Targets: []Target{
							{
								Identifier: "example.com",
								AssetType:  types.DomainName,
							},
						},
						ReportConfig: ReportConfig{
							Severity: ptr(SeverityMedium),
						},
					},
					"testdata/include/common_b.yaml": {
						Includes:    []string{"testdata/include/no_includes.yaml"},
						LavaVersion: ptr("v1.0.0"),
						ChecktypeURLs: []string{
							"checktypes_b.json",
						},
						Targets: []Target{
							{
								Identifier: "example.com",
								AssetType:  types.DomainName,
							},
						},
					},
					"testdata/include/no_includes.yaml": {
						LavaVersion: ptr("v1.0.0"),
						ChecktypeURLs: []string{
							"checktypes_no_includes.json",
						},
						Targets: []Target{
							{
								Identifier: "example.com",
								AssetType:  types.DomainName,
							},
						},
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewConfigGraph(tt.URL)
			if (err != nil) != tt.wantErr {
				t.Errorf("unexpected error: want: %v, got: %v", tt.wantErr, err)
			}
			diffOpts := []cmp.Option{
				cmp.AllowUnexported(ConfigGraph{}, dag.DAG{}),
				cmpopts.IgnoreFields(ConfigGraph{}, "dag"),
			}
			if diff := cmp.Diff(tt.want, got, diffOpts...); diff != "" {
				t.Errorf("configs mismatch (-want +got):\n%v", diff)
			}
		})
	}
}

func TestConfigGraph_Resolve(t *testing.T) {
	tests := []struct {
		name    string
		URL     string
		want    Config
		wantErr bool
	}{
		{
			name: "no includes",
			URL:  "testdata/include/no_includes.yaml",
			want: Config{
				LavaVersion: ptr("v1.0.0"),
				ChecktypeURLs: []string{
					"checktypes_no_includes.json",
				},
				Targets: []Target{
					{
						Identifier: "example.com",
						AssetType:  types.DomainName,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "local file",
			URL:  "testdata/include/local.yaml",
			want: Config{
				Includes:    []string{"testdata/include/no_includes.yaml"},
				LavaVersion: ptr("v1.0.0"),
				ChecktypeURLs: []string{
					"checktypes_no_includes.json",
					"checktypes_local.json",
				},
				Targets: []Target{
					{
						Identifier: "example.com",
						AssetType:  types.DomainName,
					},
					{
						Identifier: "example.com",
						AssetType:  types.DomainName,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "duplicated",
			URL:  "testdata/include/duplicated.yaml",
			want: Config{
				Includes: []string{
					"testdata/include/no_includes.yaml",
					"testdata/include/no_includes.yaml",
				},
				LavaVersion: ptr("v1.0.0"),
				ChecktypeURLs: []string{
					"checktypes_no_includes.json",
					"checktypes.json",
				},
				Targets: []Target{
					{
						Identifier: "example.com",
						AssetType:  types.DomainName,
					},
					{
						Identifier: "example.com",
						AssetType:  types.DomainName,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "common includes",
			URL:  "testdata/include/common.yaml",
			want: Config{
				Includes: []string{
					"testdata/include/no_includes.yaml",
					"testdata/include/no_includes.yaml",
					"testdata/include/common_a.yaml",
					"testdata/include/common_b.yaml",
				},
				LavaVersion: ptr("v1.0.0"),
				ChecktypeURLs: []string{
					"checktypes_a.json",
					"checktypes_no_includes.json",
					"checktypes_b.json",
					"checktypes_common.json",
				},
				Targets: []Target{
					{
						Identifier: "example.com",
						AssetType:  types.DomainName,
					},
					{
						Identifier: "example.com",
						AssetType:  types.DomainName,
					},
					{
						Identifier: "example.com",
						AssetType:  types.DomainName,
					},
					{
						Identifier: "example.com",
						AssetType:  types.DomainName,
					},
				},
				ReportConfig: ReportConfig{
					Severity: ptr(SeverityCritical),
				},
			},
			wantErr: false,
		},
		{
			name: "complex",
			URL:  "testdata/include/complex/1.yaml",
			want: Config{
				Includes: []string{
					"testdata/include/complex/4.yaml",
					"testdata/include/complex/5.yaml",
					"testdata/include/complex/3.yaml",
					"testdata/include/complex/6.yaml",
					"testdata/include/complex/10.yaml",
					"testdata/include/complex/11.yaml",
					"testdata/include/complex/9.yaml",
					"testdata/include/complex/12.yaml",
					"testdata/include/complex/2.yaml",
					"testdata/include/complex/7.yaml",
					"testdata/include/complex/8.yaml",
				},
				LavaVersion: ptr("v1.0.0"),
				ChecktypeURLs: []string{
					"checktypes_4.json",
					"checktypes_5.json",
					"checktypes_3.json",
					"checktypes_6.json",
					"checktypes_2.json",
					"checktypes_7.json",
					"checktypes_10.json",
					"checktypes_11.json",
					"checktypes_9.json",
					"checktypes_12.json",
					"checktypes_8.json",
					"checktypes_1.json",
				},
				Targets: []Target{
					{
						Identifier: "example.com",
						AssetType:  types.DomainName,
					},
					{
						Identifier: "example.com",
						AssetType:  types.DomainName,
					},
					{
						Identifier: "example.com",
						AssetType:  types.DomainName,
					},
					{
						Identifier: "example.com",
						AssetType:  types.DomainName,
					},
					{
						Identifier: "example.com",
						AssetType:  types.DomainName,
					},
					{
						Identifier: "example.com",
						AssetType:  types.DomainName,
					},
					{
						Identifier: "example.com",
						AssetType:  types.DomainName,
					},
					{
						Identifier: "example.com",
						AssetType:  types.DomainName,
					},
					{
						Identifier: "example.com",
						AssetType:  types.DomainName,
					},
					{
						Identifier: "example.com",
						AssetType:  types.DomainName,
					},
					{
						Identifier: "example.com",
						AssetType:  types.DomainName,
					},
					{
						Identifier: "example.com",
						AssetType:  types.DomainName,
					},
				},
				AgentConfig: AgentConfig{
					Parallel: ptr(6),
				},
				ReportConfig: ReportConfig{
					Severity: ptr(SeverityCritical),
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			graph, err := NewConfigGraph(tt.URL)
			if err != nil {
				t.Errorf("build dag: %v", err)
			}
			got := graph.Resolve()
			if (err != nil) != tt.wantErr {
				t.Errorf("unexpected error: %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("configs mismatch (-want +got):\n%v", diff)
			}
		})
	}
}
