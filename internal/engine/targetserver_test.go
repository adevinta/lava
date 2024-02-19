// Copyright 2023 Adevinta

package engine

import (
	"fmt"
	"testing"

	types "github.com/adevinta/vulcan-types"

	"github.com/adevinta/lava/internal/config"
	"github.com/adevinta/lava/internal/containers"
)

func TestGetTargetAddr(t *testing.T) {
	tests := []struct {
		name       string
		target     config.Target
		want       string
		wantNilErr bool
	}{
		{
			name: "IPv4",
			target: config.Target{
				AssetType:  types.IP,
				Identifier: "127.0.0.1",
			},
			want:       "127.0.0.1",
			wantNilErr: true,
		},
		{
			name: "IPv6",
			target: config.Target{
				AssetType:  types.IP,
				Identifier: "::1",
			},
			want:       "::1",
			wantNilErr: true,
		},
		{
			name: "Hostname",
			target: config.Target{
				AssetType:  types.Hostname,
				Identifier: "example.com",
			},
			want:       "example.com",
			wantNilErr: true,
		},
		{
			name: "WebAddress port",
			target: config.Target{
				AssetType:  types.WebAddress,
				Identifier: "https://example.com:1234/path",
			},
			want:       "example.com:1234",
			wantNilErr: true,
		},
		{
			name: "WebAddress scheme",
			target: config.Target{
				AssetType:  types.WebAddress,
				Identifier: "https://example.com/path",
			},
			want:       "example.com:443",
			wantNilErr: true,
		},
		{
			name: "WebAddress unknown scheme",
			target: config.Target{
				AssetType:  types.WebAddress,
				Identifier: "unknown://example.com/path",
			},
			want:       "example.com",
			wantNilErr: true,
		},
		{
			name: "invalid WebAddress",
			target: config.Target{
				AssetType:  types.WebAddress,
				Identifier: "https://example.com:invalidport/path",
			},
			want:       "",
			wantNilErr: false,
		},
		{
			name: "GitRepository scp-like syntax",
			target: config.Target{
				AssetType:  types.GitRepository,
				Identifier: "git@github.com:adevinta/lava.git",
			},
			want:       "github.com:22",
			wantNilErr: true,
		},
		{
			name: "GitRepository https",
			target: config.Target{
				AssetType:  types.GitRepository,
				Identifier: "https://example.com/path/to/repo.git/",
			},
			want:       "example.com:443",
			wantNilErr: true,
		},
		{
			name: "GitRepository git",
			target: config.Target{
				AssetType:  types.GitRepository,
				Identifier: "git://example.com/~user/path/to/repo.git/",
			},
			want:       "example.com:9418",
			wantNilErr: true,
		},
		{
			name: "GitRepository git port",
			target: config.Target{
				AssetType:  types.GitRepository,
				Identifier: "git://example.com:443/~user/path/to/repo.git/",
			},
			want:       "example.com:443",
			wantNilErr: true,
		},
		{
			name: "invalid GitRepository URL",
			target: config.Target{
				AssetType:  types.GitRepository,
				Identifier: "https://example.com:invalidport/path/to/repo.git/",
			},
			want:       "",
			wantNilErr: false,
		},
		{
			name: "invalid asset type",
			target: config.Target{
				AssetType:  types.IPRange,
				Identifier: "127.0.0.1/8",
			},
			want:       "",
			wantNilErr: false,
		},
		{
			name: "GitRepository with empty host",
			target: config.Target{
				AssetType:  types.GitRepository,
				Identifier: "/path",
			},
			want:       "",
			wantNilErr: false,
		},
		{
			name: "WebAddress with empty host",
			target: config.Target{
				AssetType:  types.WebAddress,
				Identifier: "/path",
			},
			want:       "",
			wantNilErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getTargetAddr(tt.target)

			if (err == nil) != tt.wantNilErr {
				t.Errorf("unexpected error: %v", err)
			}

			if got != tt.want {
				t.Errorf("unexpected host: got: %v, want: %v", got, tt.want)
			}
		})
	}
}

func TestTargetServer_mkIntIdentifier(t *testing.T) {
	cli, err := containers.NewDockerdClient(testRuntime)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer cli.Close()

	hostGatewayHostname := cli.HostGatewayHostname()

	tests := []struct {
		name       string
		target     config.Target
		want       string
		wantNilErr bool
	}{
		{
			name: "local IP",
			target: config.Target{
				Identifier: "127.0.0.1",
				AssetType:  "IP",
			},
			want:       hostGatewayHostname,
			wantNilErr: true,
		},
		{
			name: "remote IP",
			target: config.Target{
				Identifier: "192.168.1.1",
				AssetType:  "IP",
			},
			want:       hostGatewayHostname,
			wantNilErr: true,
		},
		{
			name: "local Hostname",
			target: config.Target{
				Identifier: "localhost",
				AssetType:  "Hostname",
			},
			want:       hostGatewayHostname,
			wantNilErr: true,
		},
		{
			name: "remote Hostname",
			target: config.Target{
				Identifier: "example.com",
				AssetType:  "Hostname",
			},
			want:       hostGatewayHostname,
			wantNilErr: true,
		},
		{
			name: "local WebAddress",
			target: config.Target{
				Identifier: "http://127.0.0.1:12345/path",
				AssetType:  "WebAddress",
			},
			want:       fmt.Sprintf("http://%v:12345/path", hostGatewayHostname),
			wantNilErr: true,
		},
		{
			name: "remote WebAddress",
			target: config.Target{
				Identifier: "http://192.168.1.1/path",
				AssetType:  "WebAddress",
			},
			want:       fmt.Sprintf("http://%v/path", hostGatewayHostname),
			wantNilErr: true,
		},
		{
			name: "local GitRepository",
			target: config.Target{
				Identifier: "ssh://git@localhost:12345/path/to/repo.git",
				AssetType:  "GitRepository",
			},
			want:       fmt.Sprintf("ssh://git@%v:12345/path/to/repo.git", hostGatewayHostname),
			wantNilErr: true,
		},
		{
			name: "remote GitRepository",
			target: config.Target{
				Identifier: "git@example.com:/path/to/repo.git",
				AssetType:  "GitRepository",
			},
			want:       fmt.Sprintf("ssh://git@%v/path/to/repo.git", hostGatewayHostname),
			wantNilErr: true,
		},
		{
			name: "multiple host occurrences",
			target: config.Target{
				Identifier: "localhost://localhost:12345/path",
				AssetType:  "WebAddress",
			},
			want:       fmt.Sprintf("localhost://%v:12345/path", hostGatewayHostname),
			wantNilErr: true,
		},
		{
			name: "DockerImage",
			target: config.Target{
				Identifier: "alpine:3.18",
				AssetType:  "DockerImage",
			},
			want:       "",
			wantNilErr: false,
		},
		{
			name: "invalid GitRepository",
			target: config.Target{
				Identifier: "ssh://git@localhost:invalidport/path/to/repo.git",
				AssetType:  "GitRepository",
			},
			want:       "",
			wantNilErr: false,
		},
		{
			name: "invalid WebAddress",
			target: config.Target{
				Identifier: "http://127.0.0.1:invalidport/path",
				AssetType:  "WebAddress",
			},
			want:       "",
			wantNilErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, err := newTargetServer(testRuntime)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			defer srv.Close()

			got, err := srv.mkIntIdentifier(tt.target)

			if (err == nil) != tt.wantNilErr {
				t.Errorf("unexpected error: %v", err)
			}

			if got != tt.want {
				t.Errorf("unexpected target: got: %v, want: %v", got, tt.want)
			}
		})
	}
}

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
				t.Errorf("unexpected host: got: %v, want: %v)", u.Host, tt.wantHost)
			}
		})
	}
}
