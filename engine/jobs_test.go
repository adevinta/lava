// Copyright 2023 Adevinta

package engine

import (
	"fmt"
	"testing"

	"github.com/adevinta/vulcan-agent/jobrunner"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/adevinta/lava/config"
)

func TestGenerateChecks(t *testing.T) {
	tests := []struct {
		name       string
		checktypes config.ChecktypeCatalog
		targets    []config.Target
		want       []check
		wantNilErr bool
	}{
		{
			name: "one checktype and one target",
			checktypes: config.ChecktypeCatalog{
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
					AssetType:  "DomainName",
				},
			},
			want: []check{
				{
					checktype: config.Checktype{
						Name:        "checktype1",
						Description: "checktype1 description",
						Image:       "namespace/repository:tag",
						Assets: []string{
							"DomainName",
						},
					},
					target: config.Target{
						Identifier: "example.com",
						AssetType:  "DomainName",
					},
					options: map[string]any{},
				},
			},
			wantNilErr: true,
		},
		{
			name: "target overrides checktype options",
			checktypes: config.ChecktypeCatalog{
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
					AssetType:  "DomainName",
					Options: map[string]interface{}{
						"option2": "target value 2",
					},
				},
			},
			want: []check{
				{
					checktype: config.Checktype{
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
						AssetType:  "DomainName",
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
			wantNilErr: true,
		},
		{
			name: "two checktypes and one target",
			checktypes: config.ChecktypeCatalog{
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
					AssetType:  "DomainName",
				},
			},
			want: []check{
				{
					checktype: config.Checktype{
						Name:        "checktype1",
						Description: "checktype1 description",
						Image:       "namespace/repository:tag",
						Assets: []string{
							"DomainName",
						},
					},
					target: config.Target{
						Identifier: "example.com",
						AssetType:  "DomainName",
					},
					options: map[string]any{},
				},
				{
					checktype: config.Checktype{
						Name:        "checktype2",
						Description: "checktype2 description",
						Image:       "namespace2/repository2:tag",
						Assets: []string{
							"DomainName",
						},
					},
					target: config.Target{
						Identifier: "example.com",
						AssetType:  "DomainName",
					},
					options: map[string]any{},
				},
			},
			wantNilErr: true,
		},
		{
			name: "incompatible target",
			checktypes: config.ChecktypeCatalog{
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
					AssetType:  "GitRepository",
				},
			},
			want:       nil,
			wantNilErr: true,
		},
		{
			name: "invalid target",
			checktypes: config.ChecktypeCatalog{
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
					Identifier: "not.a.hostname",
				},
			},
			want:       nil,
			wantNilErr: true,
		},
		{
			name:       "no checktypes",
			checktypes: nil,
			targets: []config.Target{
				{
					Identifier: "example.com",
					AssetType:  "GitRepository",
				},
			},
			want:       nil,
			wantNilErr: true,
		},
		{
			name: "no targets",
			checktypes: config.ChecktypeCatalog{
				"checktype1": {
					Name:        "checktype1",
					Description: "checktype1 description",
					Image:       "namespace/repository:tag",
					Assets: []string{
						"DomainName",
					},
				},
			},
			targets:    nil,
			want:       nil,
			wantNilErr: true,
		},
		{
			name: "target without asset type",
			checktypes: config.ChecktypeCatalog{
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
			want: []check{
				{
					checktype: config.Checktype{
						Name:        "checktype1",
						Description: "checktype1 description",
						Image:       "namespace/repository:tag",
						Assets: []string{
							"DomainName",
						},
					},
					target: config.Target{
						Identifier: "example.com",
						AssetType:  "DomainName",
					},
					options: map[string]any{},
				},
			},
			wantNilErr: true,
		},
		{
			name: "one checktype with two asset types and one target",
			checktypes: config.ChecktypeCatalog{
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
					// This identifier is detected as Hostname.
					Identifier: "www.example.com",
				},
			},
			want: []check{
				{
					checktype: config.Checktype{
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
						AssetType:  "Hostname",
					},
					options: map[string]any{},
				},
			},
			wantNilErr: true,
		},
		{
			name: "one checktype with two asset types and one target with two asset types",
			checktypes: config.ChecktypeCatalog{
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
					// This identifier is detected as Hostname and DomainName.
					Identifier: "example.com",
				},
			},
			want: []check{
				{
					checktype: config.Checktype{
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
						AssetType:  "Hostname",
					},
					options: map[string]any{},
				},
				{
					checktype: config.Checktype{
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
						AssetType:  "DomainName",
					},
					options: map[string]any{},
				},
			},
			wantNilErr: true,
		},
		{
			name: "one target with two asset types",
			checktypes: config.ChecktypeCatalog{
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
					// This identifier is detected as Hostname and WebAddress.
					Identifier: "https://www.example.com",
				},
			},
			want: []check{
				{
					checktype: config.Checktype{
						Name:        "checktype1",
						Description: "checktype1 description",
						Image:       "namespace/repository:tag",
						Assets: []string{
							"Hostname",
						},
					},
					target: config.Target{
						Identifier: "https://www.example.com",
						AssetType:  "Hostname",
					},
					options: map[string]any{},
				},
			},
			wantNilErr: true,
		},
		{
			name: "duplicated targets",
			checktypes: config.ChecktypeCatalog{
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
					AssetType:  "DomainName",
				},
				{
					Identifier: "example.com",
					AssetType:  "DomainName",
				},
			},
			want: []check{
				{
					checktype: config.Checktype{
						Name:        "checktype1",
						Description: "checktype1 description",
						Image:       "namespace/repository:tag",
						Assets: []string{
							"DomainName",
						},
					},
					target: config.Target{
						Identifier: "example.com",
						AssetType:  "DomainName",
					},
					options: map[string]any{},
				},
			},
			wantNilErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := generateChecks(tt.checktypes, tt.targets)
			if (err == nil) != tt.wantNilErr {
				t.Fatalf("unexpected error value: %v", err)
			}
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
		checks     []check
		want       jobList
		wantNilErr bool
	}{
		{
			name: "one check",
			checks: []check{
				{
					id: "randomID",
					checktype: config.Checktype{
						Name:        "checktype1",
						Description: "checktype1 description",
						Image:       "namespace/repository:tag",
						Assets: []string{
							"DomainName",
						},
					},
					target: config.Target{
						Identifier: "example.com",
						AssetType:  "DomainName",
					},
					options: map[string]any{},
				},
			},
			want: []jobrunner.Job{
				{
					CheckID:   "randomID",
					Image:     "namespace/repository:tag",
					Target:    "example.com",
					AssetType: "DomainName",
					Options:   "{}",
				},
			},
			wantNilErr: true,
		},
		{
			name:       "checks nil",
			checks:     nil,
			want:       nil,
			wantNilErr: true,
		},
		{
			name:       "checks empty",
			checks:     []check{},
			want:       nil,
			wantNilErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := generateJobs(tt.checks)
			if (err == nil) != tt.wantNilErr {
				t.Fatalf("unexpected error value: %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("jobs mismatch (-want +got):\n%v", diff)
			}
		})
	}
}

func TestNewJobList(t *testing.T) {
	tests := []struct {
		name       string
		checktypes config.ChecktypeCatalog
		targets    []config.Target
		want       jobList
		wantNilErr bool
	}{
		{
			name: "one checktype and one target",
			checktypes: config.ChecktypeCatalog{
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
					AssetType:  "DomainName",
				},
			},
			want: jobList{
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
			checktypes: config.ChecktypeCatalog{
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
					AssetType:  "DomainName",
				},
			},
			want: jobList{
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
			checktypes: config.ChecktypeCatalog{
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
					AssetType:  "DomainName",
				},
			},
			want: jobList{
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
			checktypes: config.ChecktypeCatalog{
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
					AssetType:  "DomainName",
				},
			},
			want:       nil,
			wantNilErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newJobList(tt.checktypes, tt.targets)
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
