// Copyright 2023 Adevinta

package engine

import (
	"fmt"
	"testing"

	types "github.com/adevinta/vulcan-types"

	"github.com/adevinta/lava/config"
)

func TestTargetAddr(t *testing.T) {
	tests := []struct {
		name       string
		target     config.Target
		want       string
		wantNilErr bool
	}{
		{
			name: "IPv4",
			target: config.Target{
				AssetType:  config.AssetType(types.IP),
				Identifier: "127.0.0.1",
			},
			want:       "127.0.0.1",
			wantNilErr: true,
		},
		{
			name: "IPv6",
			target: config.Target{
				AssetType:  config.AssetType(types.IP),
				Identifier: "::1",
			},
			want:       "::1",
			wantNilErr: true,
		},
		{
			name: "Hostname",
			target: config.Target{
				AssetType:  config.AssetType(types.Hostname),
				Identifier: "example.com",
			},
			want:       "example.com",
			wantNilErr: true,
		},
		{
			name: "WebAddress port",
			target: config.Target{
				AssetType:  config.AssetType(types.WebAddress),
				Identifier: "https://example.com:1234/path",
			},
			want:       "example.com:1234",
			wantNilErr: true,
		},
		{
			name: "WebAddress scheme",
			target: config.Target{
				AssetType:  config.AssetType(types.WebAddress),
				Identifier: "https://example.com/path",
			},
			want:       "example.com:443",
			wantNilErr: true,
		},
		{
			name: "WebAddress unknown scheme",
			target: config.Target{
				AssetType:  config.AssetType(types.WebAddress),
				Identifier: "unknown://example.com/path",
			},
			want:       "example.com",
			wantNilErr: true,
		},
		{
			name: "invalid WebAddress",
			target: config.Target{
				AssetType:  config.AssetType(types.WebAddress),
				Identifier: "https://example.com:invalidport/path",
			},
			want:       "",
			wantNilErr: false,
		},
		{
			name: "GitRepository scp-like syntax",
			target: config.Target{
				AssetType:  config.AssetType(types.GitRepository),
				Identifier: "git@github.com:adevinta/lava.git",
			},
			want:       "github.com:22",
			wantNilErr: true,
		},
		{
			name: "GitRepository https",
			target: config.Target{
				AssetType:  config.AssetType(types.GitRepository),
				Identifier: "https://example.com/path/to/repo.git/",
			},
			want:       "example.com:443",
			wantNilErr: true,
		},
		{
			name: "GitRepository git",
			target: config.Target{
				AssetType:  config.AssetType(types.GitRepository),
				Identifier: "git://example.com/~user/path/to/repo.git/",
			},
			want:       "example.com:9418",
			wantNilErr: true,
		},
		{
			name: "GitRepository git port",
			target: config.Target{
				AssetType:  config.AssetType(types.GitRepository),
				Identifier: "git://example.com:443/~user/path/to/repo.git/",
			},
			want:       "example.com:443",
			wantNilErr: true,
		},
		{
			name: "invalid GitRepository URL",
			target: config.Target{
				AssetType:  config.AssetType(types.GitRepository),
				Identifier: "https://example.com:invalidport/path/to/repo.git/",
			},
			want:       "",
			wantNilErr: false,
		},
		{
			name: "invalid asset type",
			target: config.Target{
				AssetType:  config.AssetType(types.IPRange),
				Identifier: "127.0.0.1/8",
			},
			want:       "",
			wantNilErr: false,
		},
		{
			name: "GitRepository with empty host",
			target: config.Target{
				AssetType:  config.AssetType(types.GitRepository),
				Identifier: "/path",
			},
			want:       "",
			wantNilErr: false,
		},
		{
			name: "WebAddress with empty host",
			target: config.Target{
				AssetType:  config.AssetType(types.WebAddress),
				Identifier: "/path",
			},
			want:       "",
			wantNilErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := targetAddr(tt.target)

			if (err == nil) != tt.wantNilErr {
				t.Errorf("unexpected error: %v", err)
			}

			if got != tt.want {
				t.Errorf("unexpected host: got: %q, want: %q", got, tt.want)
			}
		})
	}
}

func TestUpdateLocalTarget(t *testing.T) {
	tests := []struct {
		name           string
		target         config.Target
		wantIdentifier string
		wantNilErr     bool
	}{
		{
			name: "local IP",
			target: config.Target{
				Identifier: "127.0.0.1",
				AssetType:  "IP",
			},
			wantIdentifier: dockerInternalHost,
			wantNilErr:     true,
		},
		{
			name: "remote IP",
			target: config.Target{
				Identifier: "192.168.1.1",
				AssetType:  "IP",
			},
			wantIdentifier: "192.168.1.1",
			wantNilErr:     true,
		},
		{
			name: "local Hostname",
			target: config.Target{
				Identifier: "localhost",
				AssetType:  "Hostname",
			},
			wantIdentifier: dockerInternalHost,
			wantNilErr:     true,
		},
		{
			name: "remote Hostname",
			target: config.Target{
				Identifier: "example.com",
				AssetType:  "Hostname",
			},
			wantIdentifier: "example.com",
			wantNilErr:     true,
		},
		{
			name: "local WebAddress",
			target: config.Target{
				Identifier: "http://127.0.0.1:12345/path",
				AssetType:  "WebAddress",
			},
			wantIdentifier: fmt.Sprintf("http://%v:12345/path", dockerInternalHost),
			wantNilErr:     true,
		},
		{
			name: "remote WebAddress",
			target: config.Target{
				Identifier: "http://192.168.1.1/path",
				AssetType:  "WebAddress",
			},
			wantIdentifier: "http://192.168.1.1/path",
			wantNilErr:     true,
		},
		{
			name: "local GitRepository",
			target: config.Target{
				Identifier: "ssh://git@localhost:12345/path/to/repo.git",
				AssetType:  "GitRepository",
			},
			wantIdentifier: fmt.Sprintf("ssh://git@%v:12345/path/to/repo.git", dockerInternalHost),
			wantNilErr:     true,
		},
		{
			name: "remote GitRepository",
			target: config.Target{
				Identifier: "git@example.com:/path/to/repo.git",
				AssetType:  "GitRepository",
			},
			wantIdentifier: "ssh://git@example.com/path/to/repo.git",
			wantNilErr:     true,
		},
		{
			name: "multiple host occurrences",
			target: config.Target{
				Identifier: "localhost://localhost:12345/path",
				AssetType:  "WebAddress",
			},
			wantIdentifier: fmt.Sprintf("localhost://%v:12345/path", dockerInternalHost),
			wantNilErr:     true,
		},
		{
			name: "DockerImage",
			target: config.Target{
				Identifier: "alpine:3.18",
				AssetType:  "DockerImage",
			},
			wantIdentifier: "alpine:3.18",
			wantNilErr:     true,
		},
		{
			name: "invalid GitRepository",
			target: config.Target{
				Identifier: "ssh://git@localhost:invalidport/path/to/repo.git",
				AssetType:  "GitRepository",
			},
			wantIdentifier: "ssh://git@localhost:invalidport/path/to/repo.git",
			wantNilErr:     false,
		},
		{
			name: "invalid WebAddress",
			target: config.Target{
				Identifier: "http://127.0.0.1:invalidport/path",
				AssetType:  "WebAddress",
			},
			wantIdentifier: "http://127.0.0.1:invalidport/path",
			wantNilErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := tt.target

			err := updateLocalTarget(&target)

			if (err == nil) != tt.wantNilErr {
				t.Errorf("unexpected error: %v", err)
			}

			if target.Identifier != tt.wantIdentifier {
				t.Errorf("unexpected target: got: %q, want: %q", target.Identifier, tt.wantIdentifier)
			}
		})
	}
}
