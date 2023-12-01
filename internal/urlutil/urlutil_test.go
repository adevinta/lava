// Copyright 2023 Adevinta

package urlutil

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-containerregistry/pkg/registry"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/registry/remote"
)

func TestGet_file(t *testing.T) {
	tests := []struct {
		name       string
		rawURL     string
		want       []byte
		wantNilErr bool
	}{
		{
			name:       "valid",
			rawURL:     "testdata/content.txt",
			want:       []byte("file with content\n"),
			wantNilErr: true,
		},
		{
			name:       "empty",
			rawURL:     "testdata/empty.txt",
			want:       []byte{},
			wantNilErr: true,
		},
		{
			name:       "not exist",
			rawURL:     "testdata/not_exist",
			want:       nil,
			wantNilErr: false,
		},
		{
			name:       "empty path",
			rawURL:     "",
			want:       nil,
			wantNilErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Get(tt.rawURL)
			if (err == nil) != tt.wantNilErr {
				t.Fatalf("unexpected error: %v", err)
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("content mismatch (-want +got):\n%v", diff)
			}
		})
	}
}

func TestGet_http(t *testing.T) {
	tests := []struct {
		name        string
		handlerFunc func(http.ResponseWriter, *http.Request)
		want        []byte
		wantNilErr  bool
	}{
		{
			name: "valid",
			handlerFunc: func(writer http.ResponseWriter, request *http.Request) {
				fmt.Fprintln(writer, "response body")
			},
			want:       []byte("response body\n"),
			wantNilErr: true,
		},
		{
			name:        "empty",
			handlerFunc: func(writer http.ResponseWriter, request *http.Request) {},
			want:        []byte{},
			wantNilErr:  true,
		},
		{
			name: "not found",
			handlerFunc: func(writer http.ResponseWriter, request *http.Request) {
				http.Error(writer, "not found", http.StatusNotFound)
			},
			want:       nil,
			wantNilErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(tt.handlerFunc))
			defer ts.Close()

			got, err := Get(ts.URL)
			if (err == nil) != tt.wantNilErr {
				t.Fatalf("unexpected error: %v", err)
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("content mismatch (-want +got):\n%v", diff)
			}
		})
	}
}

func TestGet_oci(t *testing.T) {
	oldOCIPlainHTTP := ociPlainHTTP
	defer func() { ociPlainHTTP = oldOCIPlainHTTP }()

	tests := []struct {
		name       string
		file       string
		tag        string
		want       []byte
		wantNilErr bool
	}{
		{
			name:       "valid",
			file:       "testdata/content.txt",
			tag:        "v1",
			want:       []byte("file with content\n"),
			wantNilErr: true,
		},
		{
			name:       "empty",
			file:       "testdata/empty.txt",
			tag:        "v1",
			want:       []byte{},
			wantNilErr: true,
		},
		{
			name:       "not found",
			file:       "",
			tag:        "v1",
			want:       nil,
			wantNilErr: false,
		},
	}

	ociPlainHTTP = true
	nopLogger := log.New(io.Discard, "", 0)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(registry.New(registry.Logger(nopLogger)))
			defer ts.Close()

			reg := ts.Listener.Addr().String()

			if tt.file != "" {
				if err := pushArtifact(reg, tt.file, tt.tag); err != nil {
					t.Fatalf("error pushing artifact: %v", err)
				}
			}

			repo := fmt.Sprintf("oci://%v/%v:%v", reg, tt.file, tt.tag)
			got, err := Get(repo)
			if (err == nil) != tt.wantNilErr {
				t.Fatalf("unexpected error: %v", err)
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("content mismatch (-want +got):\n%v", diff)
			}
		})
	}
}

func TestGet_invalid_url(t *testing.T) {
	tests := []struct {
		name    string
		rawURL  string
		wantErr error
	}{
		{
			name:    "invalid URL scheme",
			rawURL:  "invalid://example.com/file.json",
			wantErr: ErrInvalidScheme,
		},
		{
			name:    "invalid URL",
			rawURL:  "1http://example.com/file.json",
			wantErr: ErrInvalidURL,
		},
		{
			name:    "empty OCI host",
			rawURL:  "oci:///test/repo:tag",
			wantErr: ErrInvalidURL,
		},
		{
			name:    "empty OCI repo",
			rawURL:  "oci://registry/:tag",
			wantErr: ErrInvalidURL,
		},
		{
			name:    "empty OCI tag",
			rawURL:  "oci://registry/test/repo:",
			wantErr: ErrInvalidURL,
		},
		{
			name:    "malformed OCI path",
			rawURL:  "oci:///test/repo",
			wantErr: ErrInvalidURL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Get(tt.rawURL)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("unexpected error: want: %v, got: %v", tt.wantErr, err)
			}

			if got != nil {
				t.Errorf("unexpected value: %v", got)
			}
		})
	}
}

func pushArtifact(reg, name, tag string) error {
	fs, err := file.New("")
	if err != nil {
		return fmt.Errorf("create file store: %w", err)
	}
	defer fs.Close()

	desc, err := fs.Add(context.Background(), name, "application/vnd.test.file", "")
	if err != nil {
		return fmt.Errorf("add file: %w", err)
	}

	opts := oras.PackManifestOptions{
		Layers: []ocispec.Descriptor{desc},
	}
	descManifest, err := oras.PackManifest(context.Background(), fs, oras.PackManifestVersion1_1_RC4, "application/vnd.test.manifest", opts)
	if err != nil {
		return fmt.Errorf("pack manifest: %w", err)
	}

	if err := fs.Tag(context.Background(), descManifest, tag); err != nil {
		return fmt.Errorf("tag artifact: %w", err)
	}

	repo, err := remote.NewRepository(reg + "/" + name)
	if err != nil {
		return fmt.Errorf("new repository: %w", err)
	}
	repo.PlainHTTP = true

	if _, err := oras.Copy(context.Background(), fs, tag, repo, tag, oras.DefaultCopyOptions); err != nil {
		return fmt.Errorf("copy artifact: %w", err)
	}
	return nil
}
