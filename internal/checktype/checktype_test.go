// Copyright 2023 Adevinta

package checktype

import (
	"errors"
	"os"
	"testing"

	types "github.com/adevinta/vulcan-types"
	"github.com/google/go-cmp/cmp"
)

func TestChecktype_Accepts(t *testing.T) {
	tests := []struct {
		name      string
		assetType types.AssetType
		checktype Checktype
		want      bool
	}{
		{
			name:      "accepted asset type",
			assetType: types.Hostname,
			checktype: Checktype{
				Name:        "vulcan-drupal",
				Description: "Checks for some vulnerable versions of Drupal.",
				Image:       "vulcansec/vulcan-drupal:edge",
				Assets: []string{
					"Hostname",
				},
			},
			want: true,
		},
		{
			name:      "not accepted asset type",
			assetType: types.DomainName,
			checktype: Checktype{
				Name:        "vulcan-drupal",
				Description: "Checks for some vulnerable versions of Drupal.",
				Image:       "vulcansec/vulcan-drupal:edge",
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

func TestNewCatalog(t *testing.T) {
	tests := []struct {
		name    string
		urls    []string
		want    Catalog
		wantErr error
	}{
		{
			name: "valid file",
			urls: []string{
				"testdata/checktype_catalog.json",
			},
			want: Catalog{
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
			name: "checktype catalog override",
			urls: []string{
				"testdata/checktype_catalog.json",
				"testdata/checktype_catalog_override.json",
			},
			want: Catalog{
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
				"testdata/invalid_checktype_catalog.json",
			},
			want:    nil,
			wantErr: ErrMalformedCatalog,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewCatalog(tt.urls)

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("unexpected error: want: %v, got: %v", tt.wantErr, err)
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("checktypes mismatch (-want +got):\n%v", diff)
			}
		})
	}
}
