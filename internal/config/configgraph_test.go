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
							"checktypes.json",
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
							"checktypes.json",
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
							"checktypes.json",
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
							"checktypes.json",
						},
						Targets: []Target{
							{
								Identifier: "example.com",
								AssetType:  types.DomainName,
							},
						},
					},
					"testdata/include/common_a.yaml": {
						Includes:    []string{"testdata/include/no_includes.yaml"},
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
					"testdata/include/common_b.yaml": {
						Includes:    []string{"testdata/include/no_includes.yaml"},
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
							"checktypes.json",
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
