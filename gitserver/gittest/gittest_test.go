// Copyright 2023 Adevinta

package gittest

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractTemp(t *testing.T) {
	tests := []struct {
		name       string
		tarfile    string
		wantNilErr bool
	}{
		{
			name:       "valid",
			tarfile:    "testrepo.tar",
			wantNilErr: true,
		},
		{
			name:       "invalid path",
			tarfile:    "notfound.tar",
			wantNilErr: false,
		},
		{
			name:       "invalid tar file",
			tarfile:    "invalid.tar",
			wantNilErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpPath, err := ExtractTemp(filepath.Join("testdata", tt.tarfile))
			if err != nil {
				if tt.wantNilErr {
					t.Fatalf("unexpected extract error: %v", err)
				}
				return
			}
			defer os.RemoveAll(tmpPath)

			if _, err := os.Stat(filepath.Join(tmpPath, "foo.txt")); err != nil {
				t.Fatalf("unexpected stat error: %v", err)
			}
		})
	}
}

func TestCloneTemp(t *testing.T) {
	tmpPath, err := ExtractTemp(filepath.Join("testdata", "testrepo.tar"))
	if err != nil {
		t.Fatalf("unexpected extract error: %v", err)
	}
	defer os.RemoveAll(tmpPath)

	clonePath, err := CloneTemp(tmpPath)
	if err != nil {
		t.Fatalf("unexpected clone error: %v", err)
	}

	if _, err := os.Stat(filepath.Join(clonePath, "foo.txt")); err != nil {
		t.Fatalf("unexpected stat error: %v", err)
	}
}

func TestCloneTemp_invalid_repo(t *testing.T) {
	if _, err := CloneTemp("testdata"); err == nil {
		t.Fatalf("unexpected nil error")
	}
}
