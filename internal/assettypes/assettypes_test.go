// Copyright 2023 Adevinta

package assettypes

import (
	"errors"
	"io/fs"
	"regexp"
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

func TestCheckReachable(t *testing.T) {
	tests := []struct {
		name          string
		typ           types.AssetType
		ident         string
		wantErr       error
		wantErrRegexp *regexp.Regexp
	}{
		{
			name:    "git folder",
			typ:     types.GitRepository,
			ident:   "testdata",
			wantErr: nil,
		},
		{
			name:          "git file",
			typ:           types.GitRepository,
			ident:         "testdata/foo.txt",
			wantErrRegexp: regexp.MustCompile(`^not a directory$`),
		},
		{
			name:    "git not exists",
			typ:     types.GitRepository,
			ident:   "notexists",
			wantErr: ErrUnsupported,
		},
		{
			name:    "path folder",
			typ:     Path,
			ident:   "testdata",
			wantErr: nil,
		},
		{
			name:    "path file",
			typ:     Path,
			ident:   "testdata/foo.txt",
			wantErr: nil,
		},
		{
			name:    "path not exists",
			typ:     Path,
			ident:   "notexists",
			wantErr: fs.ErrNotExist,
		},
		{
			name:    "unsupported asset type",
			typ:     types.AWSAccount,
			ident:   "012345678901",
			wantErr: ErrUnsupported,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckReachable(tt.typ, tt.ident)
			switch {
			case tt.wantErr != nil:
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("unexpected error: got: %v, want: %v", err, tt.wantErr)
				}
			case tt.wantErrRegexp != nil:
				if err == nil {
					t.Errorf("unexpected nil error: want: %v", tt.wantErrRegexp)
				} else if !tt.wantErrRegexp.MatchString(err.Error()) {
					t.Errorf("unexpected error: got: %v, want: %v", err, tt.wantErrRegexp)
				}
			default:
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}
