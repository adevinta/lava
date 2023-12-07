// Copyright 2023 Adevinta

package engine

import (
	"fmt"
	"testing"

	"github.com/adevinta/vulcan-agent/jobrunner"
	checkcatalog "github.com/adevinta/vulcan-check-catalog/pkg/model"
	types "github.com/adevinta/vulcan-types"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/adevinta/lava/internal/assettype"
	"github.com/adevinta/lava/internal/checktypes"
	"github.com/adevinta/lava/internal/config"
)

func TestGenerateChecks(t *testing.T) {
	tests := []struct {
		name    string
		catalog checktypes.Catalog
		targets []config.Target
		want    []check
	}{
		{
			name: "one checktype and one target",
			catalog: checktypes.Catalog{
				"checktype1": {
					Name:        "checktype1",
					Description: "checktype1 description",
					Image:       "namespace/repository:tag",
					Assets: []string{
						"DomainName",
					},
				},
			},
			targets: []config.Target{
				{
					Identifier: "example.com",
					AssetType:  types.DomainName,
				},
			},
			want: []check{
				{
					checktype: checkcatalog.Checktype{
						Name:        "checktype1",
						Description: "checktype1 description",
						Image:       "namespace/repository:tag",
						Assets: []string{
							"DomainName",
						},
					},
					target: config.Target{
						Identifier: "example.com",
						AssetType:  types.DomainName,
					},
					options: map[string]any{},
				},
			},
		},
		{
			name: "target overrides checktype options",
			catalog: checktypes.Catalog{
				"checktype1": {
					Name:        "checktype1",
					Description: "checktype1 description",
					Image:       "namespace/repository:tag",
					Assets: []string{
						"DomainName",
					},
					Options: map[string]interface{}{
						"option1": "checktype value 1",
						"option2": "checktype value 2",
						"option3": "checktype value 3",
					},
				},
			},
			targets: []config.Target{
				{
					Identifier: "example.com",
					AssetType:  types.DomainName,
					Options: map[string]interface{}{
						"option2": "target value 2",
					},
				},
			},
			want: []check{
				{
					checktype: checkcatalog.Checktype{
						Name:        "checktype1",
						Description: "checktype1 description",
						Image:       "namespace/repository:tag",
						Assets: []string{
							"DomainName",
						},
						Options: map[string]interface{}{
							"option1": "checktype value 1",
							"option2": "checktype value 2",
							"option3": "checktype value 3",
						},
					},
					target: config.Target{
						Identifier: "example.com",
						AssetType:  types.DomainName,
						Options: map[string]interface{}{
							"option2": "target value 2",
						},
					},
					options: map[string]interface{}{
						"option1": "checktype value 1",
						"option2": "target value 2",
						"option3": "checktype value 3",
					},
				},
			},
		},
		{
			name: "two checktypes and one target",
			catalog: checktypes.Catalog{
				"checktype1": {
					Name:        "checktype1",
					Description: "checktype1 description",
					Image:       "namespace/repository:tag",
					Assets: []string{
						"DomainName",
					},
				},
				"checktype2": {
					Name:        "checktype2",
					Description: "checktype2 description",
					Image:       "namespace2/repository2:tag",
					Assets: []string{
						"DomainName",
					},
				},
			},
			targets: []config.Target{
				{
					Identifier: "example.com",
					AssetType:  types.DomainName,
				},
			},
			want: []check{
				{
					checktype: checkcatalog.Checktype{
						Name:        "checktype1",
						Description: "checktype1 description",
						Image:       "namespace/repository:tag",
						Assets: []string{
							"DomainName",
						},
					},
					target: config.Target{
						Identifier: "example.com",
						AssetType:  types.DomainName,
					},
					options: map[string]any{},
				},
				{
					checktype: checkcatalog.Checktype{
						Name:        "checktype2",
						Description: "checktype2 description",
						Image:       "namespace2/repository2:tag",
						Assets: []string{
							"DomainName",
						},
					},
					target: config.Target{
						Identifier: "example.com",
						AssetType:  types.DomainName,
					},
					options: map[string]any{},
				},
			},
		},
		{
			name: "incompatible target",
			catalog: checktypes.Catalog{
				"checktype1": {
					Name:        "checktype1",
					Description: "checktype1 description",
					Image:       "namespace/repository:tag",
					Assets: []string{
						"DomainName",
					},
				},
			},
			targets: []config.Target{
				{
					Identifier: "example.com",
					AssetType:  types.GitRepository,
				},
			},
			want: nil,
		},
		{
			name: "invalid target asset type",
			catalog: checktypes.Catalog{
				"checktype1": {
					Name:        "checktype1",
					Description: "checktype1 description",
					Image:       "namespace/repository:tag",
					Assets: []string{
						"Hostname",
					},
				},
			},
			targets: []config.Target{
				{
					Identifier: "example.com",
					AssetType:  "InvalidAssetType",
				},
			},
			want: nil,
		},
		{
			name:    "no checktypes",
			catalog: nil,
			targets: []config.Target{
				{
					Identifier: "example.com",
					AssetType:  types.GitRepository,
				},
			},
			want: nil,
		},
		{
			name: "no targets",
			catalog: checktypes.Catalog{
				"checktype1": {
					Name:        "checktype1",
					Description: "checktype1 description",
					Image:       "namespace/repository:tag",
					Assets: []string{
						"DomainName",
					},
				},
			},
			targets: nil,
			want:    nil,
		},
		{
			name: "target without asset type",
			catalog: checktypes.Catalog{
				"checktype1": {
					Name:        "checktype1",
					Description: "checktype1 description",
					Image:       "namespace/repository:tag",
					Assets: []string{
						"DomainName",
					},
				},
			},
			targets: []config.Target{
				{
					Identifier: "example.com",
				},
			},
			want: nil,
		},
		{
			name: "one checktype with two asset types and one target",
			catalog: checktypes.Catalog{
				"checktype1": {
					Name:        "checktype1",
					Description: "checktype1 description",
					Image:       "namespace/repository:tag",
					Assets: []string{
						"Hostname",
						"WebAddress",
					},
				},
			},
			targets: []config.Target{
				{
					Identifier: "www.example.com",
					AssetType:  types.Hostname,
				},
			},
			want: []check{
				{
					checktype: checkcatalog.Checktype{
						Name:        "checktype1",
						Description: "checktype1 description",
						Image:       "namespace/repository:tag",
						Assets: []string{
							"Hostname",
							"WebAddress",
						},
					},
					target: config.Target{
						Identifier: "www.example.com",
						AssetType:  types.Hostname,
					},
					options: map[string]any{},
				},
			},
		},
		{
			name: "one checktype with two asset types and one target identifier with two asset types",
			catalog: checktypes.Catalog{
				"checktype1": {
					Name:        "checktype1",
					Description: "checktype1 description",
					Image:       "namespace/repository:tag",
					Assets: []string{
						"Hostname",
						"DomainName",
					},
				},
			},
			targets: []config.Target{
				{
					Identifier: "example.com",
					AssetType:  types.DomainName,
				},
				{
					Identifier: "example.com",
					AssetType:  types.Hostname,
				},
			},
			want: []check{
				{
					checktype: checkcatalog.Checktype{
						Name:        "checktype1",
						Description: "checktype1 description",
						Image:       "namespace/repository:tag",
						Assets: []string{
							"Hostname",
							"DomainName",
						},
					},
					target: config.Target{
						Identifier: "example.com",
						AssetType:  types.Hostname,
					},
					options: map[string]any{},
				},
				{
					checktype: checkcatalog.Checktype{
						Name:        "checktype1",
						Description: "checktype1 description",
						Image:       "namespace/repository:tag",
						Assets: []string{
							"Hostname",
							"DomainName",
						},
					},
					target: config.Target{
						Identifier: "example.com",
						AssetType:  types.DomainName,
					},
					options: map[string]any{},
				},
			},
		},
		{
			name: "one target identifier with two asset types",
			catalog: checktypes.Catalog{
				"checktype1": {
					Name:        "checktype1",
					Description: "checktype1 description",
					Image:       "namespace/repository:tag",
					Assets: []string{
						"Hostname",
					},
				},
			},
			targets: []config.Target{
				{
					Identifier: "https://www.example.com",
					AssetType:  types.Hostname,
				},
				{
					Identifier: "https://www.example.com",
					AssetType:  types.WebAddress,
				},
			},
			want: []check{
				{
					checktype: checkcatalog.Checktype{
						Name:        "checktype1",
						Description: "checktype1 description",
						Image:       "namespace/repository:tag",
						Assets: []string{
							"Hostname",
						},
					},
					target: config.Target{
						Identifier: "https://www.example.com",
						AssetType:  types.Hostname,
					},
					options: map[string]any{},
				},
			},
		},
		{
			name: "duplicated targets",
			catalog: checktypes.Catalog{
				"checktype1": {
					Name:        "checktype1",
					Description: "checktype1 description",
					Image:       "namespace/repository:tag",
					Assets: []string{
						"DomainName",
					},
				},
			},
			targets: []config.Target{
				{
					Identifier: "example.com",
					AssetType:  types.DomainName,
				},
				{
					Identifier: "example.com",
					AssetType:  types.DomainName,
				},
			},
			want: []check{
				{
					checktype: checkcatalog.Checktype{
						Name:        "checktype1",
						Description: "checktype1 description",
						Image:       "namespace/repository:tag",
						Assets: []string{
							"DomainName",
						},
					},
					target: config.Target{
						Identifier: "example.com",
						AssetType:  types.DomainName,
					},
					options: map[string]any{},
				},
			},
		},
		{
			name: "lava asset type",
			catalog: checktypes.Catalog{
				"checktype1": {
					Name:        "checktype1",
					Description: "checktype1 description",
					Image:       "namespace/repository:tag",
					Assets: []string{
						"GitRepository",
					},
				},
			},
			targets: []config.Target{
				{
					Identifier: ".",
					AssetType:  assettype.Path,
				},
			},
			want: []check{
				{
					checktype: checkcatalog.Checktype{
						Name:        "checktype1",
						Description: "checktype1 description",
						Image:       "namespace/repository:tag",
						Assets: []string{
							"GitRepository",
						},
					},
					target: config.Target{
						Identifier: ".",
						AssetType:  assettype.Path,
					},
					options: map[string]any{},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := generateChecks(tt.catalog, tt.targets)
			diffOpts := []cmp.Option{
				cmp.AllowUnexported(check{}),
				cmpopts.SortSlices(checkLess),
				cmpopts.IgnoreFields(check{}, "id"),
			}
			if diff := cmp.Diff(tt.want, got, diffOpts...); diff != "" {
				t.Errorf("checks mismatch (-want +got):\n%v", diff)
			}
		})
	}
}

func TestGenerateJobs(t *testing.T) {
	tests := []struct {
		name       string
		catalog    checktypes.Catalog
		targets    []config.Target
		want       []jobrunner.Job
		wantNilErr bool
	}{
		{
			name: "one checktype and one target",
			catalog: checktypes.Catalog{
				"checktype1": {
					Name:        "checktype1",
					Description: "checktype1 description",
					Image:       "namespace/repository:tag",
					Assets: []string{
						"DomainName",
					},
				},
			},
			targets: []config.Target{
				{
					Identifier: "example.com",
					AssetType:  types.DomainName,
				},
			},
			want: []jobrunner.Job{
				{
					Image:     "namespace/repository:tag",
					Target:    "example.com",
					AssetType: "DomainName",
					Options:   "{}",
				},
			},
			wantNilErr: true,
		},
		{
			name: "two checktypes and one target",
			catalog: checktypes.Catalog{
				"checktype1": {
					Name:        "checktype1",
					Description: "checktype1 description",
					Image:       "namespace/repository:tag",
					Assets: []string{
						"DomainName",
					},
				},
				"checktype2": {
					Name:        "checktype2",
					Description: "checktype2 description",
					Image:       "namespace2/repository2:tag",
					Assets: []string{
						"DomainName",
					},
				},
			},
			targets: []config.Target{
				{
					Identifier: "example.com",
					AssetType:  types.DomainName,
				},
			},
			want: []jobrunner.Job{
				{
					Image:     "namespace/repository:tag",
					Target:    "example.com",
					AssetType: "DomainName",
					Options:   "{}",
				},
				{
					Image:     "namespace2/repository2:tag",
					Target:    "example.com",
					AssetType: "DomainName",
					Options:   "{}",
				},
			},
			wantNilErr: true,
		},
		{
			name: "one checktype and one target with valid required vars",
			catalog: checktypes.Catalog{
				"checktype1": {
					Name:        "checktype1",
					Description: "checktype1 description",
					Image:       "namespace/repository:tag",
					Assets: []string{
						"DomainName",
					},
					RequiredVars: []any{
						"REQUIRED_VAR_1",
						"REQUIRED_VAR_2",
					},
				},
			},
			targets: []config.Target{
				{
					Identifier: "example.com",
					AssetType:  types.DomainName,
				},
			},
			want: []jobrunner.Job{
				{
					Image:     "namespace/repository:tag",
					Target:    "example.com",
					AssetType: "DomainName",
					Options:   "{}",
					RequiredVars: []string{
						"REQUIRED_VAR_1",
						"REQUIRED_VAR_2",
					},
				},
			},
			wantNilErr: true,
		},
		{
			name: "one checktype and one target with invalid required vars",
			catalog: checktypes.Catalog{
				"checktype1": {
					Name:        "checktype1",
					Description: "checktype1 description",
					Image:       "namespace/repository:tag",
					Assets: []string{
						"DomainName",
					},
					RequiredVars: []int{
						1,
						2,
					},
				},
			},
			targets: []config.Target{
				{
					Identifier: "example.com",
					AssetType:  types.DomainName,
				},
			},
			want:       nil,
			wantNilErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := generateJobs(tt.catalog, tt.targets)
			if (err == nil) != tt.wantNilErr {
				t.Fatalf("unexpected error value: %v", err)
			}
			diffOpts := []cmp.Option{
				cmpopts.SortSlices(jobLess),
				cmpopts.IgnoreFields(jobrunner.Job{}, "CheckID"),
			}
			if diff := cmp.Diff(tt.want, got, diffOpts...); diff != "" {
				t.Errorf("checks mismatch (-want +got):\n%v", diff)
			}
		})
	}
}

func checkLess(a, b check) bool {
	h := func(c check) string {
		c.id = ""
		return fmt.Sprintf("%#v", c)
	}
	return h(a) < h(b)
}

func jobLess(a, b jobrunner.Job) bool {
	h := func(j jobrunner.Job) string {
		j.CheckID = ""
		return fmt.Sprintf("%#v", j)
	}
	return h(a) < h(b)
}
