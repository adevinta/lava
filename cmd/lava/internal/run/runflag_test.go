// Copyright 2024 Adevinta

package run

import (
	"bytes"
	"os"
	"testing"

	types "github.com/adevinta/vulcan-types"
	"github.com/google/go-cmp/cmp"

	"github.com/adevinta/lava/internal/assettypes"
)

func TestTypeFlag_Set(t *testing.T) {
	tests := []struct {
		name       string
		values     []string
		want       typeFlag
		wantNilErr []bool
	}{
		{
			name:       "valid",
			values:     []string{"Path"},
			want:       typeFlag(assettypes.Path),
			wantNilErr: []bool{true},
		},
		{
			name:       "invalid",
			values:     []string{"Invalid"},
			want:       typeFlag(""),
			wantNilErr: []bool{false},
		},
		{
			name:       "empty",
			values:     []string{""},
			want:       typeFlag(""),
			wantNilErr: []bool{false},
		},
		{
			name:       "multiple",
			values:     []string{"Path", "Hostname"},
			want:       typeFlag(types.Hostname),
			wantNilErr: []bool{true, true},
		},
		{
			name:       "multiple valid invalid",
			values:     []string{"Path", "Invalid", "Hostname", "Invalid"},
			want:       typeFlag(types.Hostname),
			wantNilErr: []bool{true, false, true, false},
		},
	}

	for _, tt := range tests {
		if len(tt.values) != len(tt.wantNilErr) {
			panic("values and wantNilErr arrays must have the same length")
		}

		t.Run(tt.name, func(t *testing.T) {
			var got typeFlag
			for i, v := range tt.values {
				if err := got.Set(v); (err == nil) != tt.wantNilErr[i] {
					t.Errorf("unexpected error: %v", err)
				}
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("asset type mismatch (-want +got):\n%v", diff)
			}
		})
	}
}

func TestVarFlag_Set(t *testing.T) {
	tests := []struct {
		name       string
		values     []string
		env        map[string]string
		want       varFlag
		wantNilErr []bool
	}{
		{
			name:       "valid",
			values:     []string{"name1=value1"},
			want:       varFlag{"name1": "value1"},
			wantNilErr: []bool{true},
		},
		{
			name:       "multiple equals",
			values:     []string{"name1=value1=value2"},
			want:       varFlag{"name1": "value1=value2"},
			wantNilErr: []bool{true},
		},
		{
			name:       "empty",
			values:     []string{""},
			want:       varFlag{},
			wantNilErr: []bool{false},
		},
		{
			name:       "empty value",
			values:     []string{"name1="},
			want:       varFlag{"name1": ""},
			wantNilErr: []bool{true},
		},
		{
			name:       "empty name",
			values:     []string{"=value1"},
			want:       varFlag{},
			wantNilErr: []bool{false},
		},
		{
			name:   "known env",
			values: []string{"name1"},
			env: map[string]string{
				"name1": "env1",
			},
			want:       varFlag{"name1": "env1"},
			wantNilErr: []bool{true},
		},
		{
			name:       "unknown env",
			values:     []string{"unknown"},
			want:       varFlag{"unknown": ""},
			wantNilErr: []bool{true},
		},
		{
			name:   "same env name",
			values: []string{"name1=value1", "name2="},
			env: map[string]string{
				"name1": "env1",
				"name2": "env2",
			},
			want:       varFlag{"name1": "value1", "name2": ""},
			wantNilErr: []bool{true, true},
		},
		{
			name:       "multiple",
			values:     []string{"name1=", "name2=value2"},
			want:       varFlag{"name1": "", "name2": "value2"},
			wantNilErr: []bool{true, true},
		},
		{
			name:   "multiple valid invalid env",
			values: []string{"name1=value1", "=value2", "name3=", "=value4", "name5"},
			env: map[string]string{
				"name1": "env1",
				"name3": "env3",
				"name5": "env5",
			},
			want:       varFlag{"name1": "value1", "name3": "", "name5": "env5"},
			wantNilErr: []bool{true, false, true, false, true},
		},
	}

	for _, tt := range tests {
		if len(tt.values) != len(tt.wantNilErr) {
			panic("values and wantNilErr arrays must have the same length")
		}

		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			var got varFlag
			for i, v := range tt.values {
				if err := got.Set(v); (err == nil) != tt.wantNilErr[i] {
					t.Errorf("unexpected error: %v", err)
				}
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("envvars mismatch (-want +got):\n%v", diff)
			}
		})
	}
}

func TestUserFlag_Set(t *testing.T) {
	tests := []struct {
		name       string
		values     []string
		stdin      string
		want       userFlag
		wantNilErr []bool
	}{
		{
			name:   "valid",
			values: []string{"user:pass"},
			want: userFlag{
				Username: "user",
				Password: "pass",
			},
			wantNilErr: []bool{true},
		},
		{
			name:       "empty",
			values:     []string{""},
			want:       userFlag{},
			wantNilErr: []bool{false},
		},
		{
			name: "multiple",
			values: []string{
				"user1:pass1",
				"user2:pass2",
			},
			want: userFlag{
				Username: "user2",
				Password: "pass2",
			},
			wantNilErr: []bool{true, true},
		},
		{
			name: "multiple valid empty",
			values: []string{
				"user1:pass1",
				"",
				"user3:pass3",
				"",
			},
			want: userFlag{
				Username: "user3",
				Password: "pass3",
			},
			wantNilErr: []bool{true, false, true, false},
		},
		{
			name: "empty password",
			values: []string{
				"user1:",
			},
			want: userFlag{
				Username: "user1",
				Password: "",
			},
			wantNilErr: []bool{true},
		},
		{
			name: "stdin",
			values: []string{
				"user1",
			},
			stdin: "pass1",
			want: userFlag{
				Username: "user1",
				Password: "pass1",
			},
			wantNilErr: []bool{true},
		},
		{
			name: "multiple stdin",
			values: []string{
				"user1",
				"user2",
			},
			stdin: "pass1",
			want: userFlag{
				Username: "user2",
				Password: "",
			},
			wantNilErr: []bool{true, true},
		},
	}

	for _, tt := range tests {
		if len(tt.values) != len(tt.wantNilErr) {
			panic("values and wantNilErr arrays must have the same length")
		}

		t.Run(tt.name, func(t *testing.T) {
			if tt.stdin != "" {
				osStdin = bytes.NewBufferString(tt.stdin)
				defer func() { osStdin = os.Stdin }()
			}

			var got userFlag
			for i, v := range tt.values {
				if err := got.Set(v); (err == nil) != tt.wantNilErr[i] {
					t.Errorf("unexpected error: %v", err)
				}
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("userinfo mismatch (-want +got):\n%v", diff)
			}
		})
	}
}
