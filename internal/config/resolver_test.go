// Copyright 2024 Adevinta

package config

import (
	"testing"

	types "github.com/adevinta/vulcan-types"
	"github.com/google/go-cmp/cmp"
)

func TestResolver_Resolve(t *testing.T) {
	tests := []struct {
		name    string
		URL     string
		want    Config
		wantErr bool
	}{
		{
			name: "File without includes",
			URL:  "testdata/includes/without_includes.yaml",
			want: Config{
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
			wantErr: false,
		},
		{
			name: "Include a local file",
			URL:  "testdata/includes/include_local.yaml",
			want: Config{
				Includes:    []string{"testdata/includes/without_includes.yaml"},
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
			wantErr: false,
		},
		{
			name:    "Import itself",
			URL:     "testdata/includes/autoinclude.yaml",
			wantErr: true,
		},
		{
			name: "Include duplicated",
			URL:  "testdata/includes/include_duplicated.yaml",
			want: Config{
				Includes: []string{
					"testdata/includes/without_includes.yaml",
					"testdata/includes/without_includes.yaml",
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
			wantErr: false,
		},
		{
			name: "Include two with common include",
			URL:  "testdata/includes/include_two_with_common_include.yaml",
			want: Config{
				Includes: []string{
					"testdata/includes/include_a.yaml",
					"testdata/includes/include_b.yaml",
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
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newResolver(tt.URL)
			got, err := r.resolve()
			if (err != nil) != tt.wantErr {
				t.Errorf("unexpected error: want: %v, got: %v", tt.wantErr, err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("configs mismatch (-want +got):\n%v", diff)
			}
		})
	}
}