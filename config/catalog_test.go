// Copyright 2023 Adevinta

package config

import (
	"errors"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestNewChecktypeCatalog(t *testing.T) {
	tests := []struct {
		name    string
		urls    []string
		want    ChecktypeCatalog
		wantErr error
	}{
		{
			name: "valid file",
			urls: []string{
				"testdata/checktypes_catalog.json",
			},
			want: ChecktypeCatalog{
				"vulcan-drupal": {
					Name:        "vulcan-drupal",
					Description: "Checks for some vulnerable versions of Drupal.",
					Image:       "vulcansec/vulcan-drupal:edge",
					Assets: []string{
						"Hostname",
					},
					RequiredVars: []any{
						"REQUIRED_VAR_1",
					},
				},
			},
			wantErr: nil,
		},
		{
			name: "checktypes_catalog_override",
			urls: []string{
				"testdata/checktypes_catalog.json",
				"testdata/checktypes_catalog_override.json",
			},
			want: ChecktypeCatalog{
				"vulcan-drupal": {
					Name:        "vulcan-drupal",
					Description: "Checks for some vulnerable versions of Drupal (overridden).",
					Image:       "vulcansec/vulcan-drupal:overridden",
					Assets: []string{
						"Hostname",
					},
				},
			},
			wantErr: nil,
		},
		{
			name: "wrong file",
			urls: []string{
				"testdata/not_exists",
			},
			want:    nil,
			wantErr: os.ErrNotExist,
		},
		{
			name: "invalid file",
			urls: []string{
				"testdata/invalid_checktypes_catalog.json",
			},
			want:    nil,
			wantErr: ErrMalformedCatalog,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewChecktypeCatalog(tt.urls)

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("unexpected error: want: %v, got: %v", tt.wantErr, err)
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("checktypes mismatch (-want +got):\n%v", diff)
			}
		})
	}
}

func TestChecktypeAccepts(t *testing.T) {
	tests := []struct {
		name      string
		assetType AssetType
		checktype Checktype
		want      bool
	}{
		{
			name:      "accepted asset type",
			assetType: AssetType("Hostname"),
			checktype: Checktype{
				Name:        "vulcan-drupal",
				Description: "Checks for some vulnerable versions of Drupal (overridden).",
				Image:       "vulcansec/vulcan-drupal:overridden",
				Assets: []string{
					"Hostname",
				},
			},
			want: true,
		},
		{
			name:      "not accepted asset type",
			assetType: AssetType("DomainName"),
			checktype: Checktype{
				Name:        "vulcan-drupal",
				Description: "Checks for some vulnerable versions of Drupal (overridden).",
				Image:       "vulcansec/vulcan-drupal:overridden",
				Assets: []string{
					"Hostname",
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.checktype.Accepts(tt.assetType)
			if got != tt.want {
				t.Errorf("unexpected return value: want: %v, got: %v", got, tt.want)
			}
		})
	}
}
