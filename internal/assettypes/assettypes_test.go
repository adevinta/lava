// Copyright 2023 Adevinta

package assettypes

import (
	"testing"

	types "github.com/adevinta/vulcan-types"
)

func TestIsValid(t *testing.T) {
	tests := []struct {
		name string
		at   types.AssetType
		want bool
	}{
		{
			name: "lava type",
			at:   Path,
			want: true,
		},
		{
			name: "vulcan type",
			at:   types.Hostname,
			want: false,
		},
		{
			name: "zero value",
			at:   types.AssetType(""),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsValid(tt.at)
			if got != tt.want {
				t.Errorf("unexpected value: want: %v, got: %v", tt.want, got)
			}
		})
	}
}

func TestToVulcan(t *testing.T) {
	tests := []struct {
		name string
		at   types.AssetType
		want types.AssetType
	}{
		{
			name: "lava type",
			at:   Path,
			want: types.GitRepository,
		},
		{
			name: "vulcan type",
			at:   types.Hostname,
			want: types.Hostname,
		},
		{
			name: "zero value",
			at:   types.AssetType(""),
			want: types.AssetType(""),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ToVulcan(tt.at)
			if got != tt.want {
				t.Errorf("unexpected value: want: %v, got: %v", tt.want, got)
			}
		})
	}
}
