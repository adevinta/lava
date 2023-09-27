// Copyright 2023 Adevinta

// Package urlutil provides utilities for working with URLs.
package urlutil

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
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
// It supports the following schemes: http, https. If the provided URL
// does not specify a scheme, it is considered a file path. In the
// case of http and https, the contents are retrieved issuing an HTTP
// GET request.
func Get(rawURL string) ([]byte, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidURL, err)
	}

	switch parsedURL.Scheme {
	case "http", "https":
		return getHTTP(parsedURL)
	case "":
		return os.ReadFile(parsedURL.Path)
	}
	return nil, fmt.Errorf("%w: %v", ErrInvalidScheme, parsedURL.Scheme)
}

// getHTTP retrieves the contents of a given HTTP URL.
func getHTTP(parsedURL *url.URL) ([]byte, error) {
	resp, err := http.Get(parsedURL.String())
	if err != nil {
		return nil, fmt.Errorf("get %q: %w", parsedURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get %q: %w", parsedURL, err)
	}
	return io.ReadAll(resp.Body)
}
