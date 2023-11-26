// Copyright 2023 Adevinta

// Package urlutil provides utilities for working with URLs.
package urlutil

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry/remote"
)

var (
	// ErrInvalidScheme is returned by [Get] when the scheme of
	// the provided URL is not supported.
	ErrInvalidScheme = errors.New("invalid scheme")

	// ErrInvalidURL is returned by [Get] when the provided URL is
	// not valid.
	ErrInvalidURL = errors.New("invalid URL")
)

// Get retrieves the contents from a given raw URL. It returns error
// if the URL is not valid or if it is not possible to get the
// contents.
//
// It supports the following schemes: http, https and oci. If the
// provided URL does not specify a scheme, it is considered a file
// path. In the case of http and https, the contents are retrieved
// issuing an HTTP GET request. In the case of oci, an OCI artifact is
// retrieved.
func Get(rawURL string) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidURL, err)
	}

	switch u.Scheme {
	case "http", "https":
		return getHTTP(u)
	case "oci":
		return getOCI(u)
	case "":
		return os.ReadFile(u.Path)
	}
	return nil, fmt.Errorf("%w: %v", ErrInvalidScheme, u.Scheme)
}

// getHTTP retrieves the contents of a given HTTP URL.
func getHTTP(u *url.URL) ([]byte, error) {
	resp, err := http.Get(u.String())
	if err != nil {
		return nil, fmt.Errorf("get %q: %w", u, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get %q: %w", u, err)
	}
	return io.ReadAll(resp.Body)
}

// ociPlainHTTP is set by the tests to force plain HTTP connections
// when retrieving OCI artifacts.
var ociPlainHTTP bool

// getOCI retrieves the contents of a given OCI artifact. It expects
// one single file.
func getOCI(u *url.URL) ([]byte, error) {
	if u.Host == "" {
		return nil, fmt.Errorf("%w: empty host", ErrInvalidURL)
	}

	parts := strings.Split(u.Path, ":")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, fmt.Errorf("%w: malformed path: %q", ErrInvalidURL, u.Path)
	}
	repo := u.Host + parts[0]
	tag := parts[1]

	src, err := remote.NewRepository(repo)
	if err != nil {
		return nil, fmt.Errorf("%w: new repository: %w", ErrInvalidURL, err)
	}
	src.PlainHTTP = ociPlainHTTP

	desc, err := oras.Resolve(context.Background(), src, tag, oras.DefaultResolveOptions)
	if err != nil {
		return nil, fmt.Errorf("resolve: %w", err)
	}

	successors, err := content.Successors(context.Background(), src, desc)
	if err != nil {
		return nil, fmt.Errorf("artifact successors: %w", err)
	}

	for _, s := range successors {
		// The title annotation is used to store the file
		// name. We are only interested in regular files, so
		// we can skip successors with no title.
		if s.Annotations[ocispec.AnnotationTitle] == "" {
			continue
		}

		data, err := content.FetchAll(context.Background(), src, s)
		if err != nil {
			return nil, fmt.Errorf("artifact fetch: %w", err)
		}
		return data, nil
	}

	return nil, errors.New("malformed artifact")
}
