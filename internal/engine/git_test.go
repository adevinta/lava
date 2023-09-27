// Copyright 2023 Adevinta

package engine

import "testing"

func TestParseGitURL(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		wantHost string
	}{
		{
			name:     "url",
			url:      "https://example.com:443/path/to/repo.git/",
			wantHost: "example.com:443",
		},
		{
			name:     "scp long",
			url:      "user@example.com:/~user/path/to/repo.git/",
			wantHost: "example.com",
		},
		{
			name:     "scp short",
			url:      "example.com:/",
			wantHost: "example.com",
		},
		{
			name:     "local path",
			url:      "/path/to/repo.git/",
			wantHost: "",
		},
		{
			name:     "scp with colon",
			url:      "foo:bar",
			wantHost: "foo",
		},
		{
			name:     "local path with colon",
			url:      "./foo:bar",
			wantHost: "",
		},
		{
			name:     "slash",
			url:      "/",
			wantHost: "",
		},
		{
			name:     "colon",
			url:      ":",
			wantHost: "",
		},
		{
			name:     "colon slash",
			url:      ":/",
			wantHost: "",
		},
		{
			name:     "slash colon",
			url:      "/:",
			wantHost: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := parseGitURL(tt.url)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if u.Host != tt.wantHost {
				t.Errorf("unexpected host: got: %q, want: %q)", u.Host, tt.wantHost)
			}
		})
	}
}
