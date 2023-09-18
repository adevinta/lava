// Copyright 2023 Adevinta

package engine

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	agentconfig "github.com/adevinta/vulcan-agent/config"
	report "github.com/adevinta/vulcan-report"
	types "github.com/adevinta/vulcan-types"
	dockertypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/pkg/archive"

	"github.com/adevinta/lava/config"
	"github.com/adevinta/lava/dockerutil"
)

func TestMain(m *testing.M) {
	flag.Parse()

	level := slog.LevelError
	if testing.Verbose() {
		level = slog.LevelDebug
	}

	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(h))

	os.Exit(m.Run())
}

func TestRun(t *testing.T) {
	if err := dockerBuild("testdata/engine/lava-engine-test", "lava-engine-test:latest"); err != nil {
		t.Fatalf("could build Docker image: %v", err)
	}

	wantDetails := fmt.Sprintf("lava engine test response %v", rand.Uint64())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, wantDetails)
	}))
	defer srv.Close()

	t.Logf("test server listening at %v", srv.URL)

	var (
		checktypesURLs = []string{"testdata/engine/checktypes_lava_engine_test.json"}
		targets        = []config.Target{
			{
				Identifier: srv.URL,
				AssetType:  config.AssetType(types.WebAddress),
			},
		}
		agentConfig = config.AgentConfig{
			PullPolicy: agentconfig.PullPolicyNever,
		}
	)

	engineReport, err := Run(checktypesURLs, targets, agentConfig)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var checkReports []report.Report
	for _, v := range engineReport {
		checkReports = append(checkReports, v)
	}

	if len(checkReports) != 1 {
		t.Fatalf("unexpected number of reports: %v", len(checkReports))
	}

	gotReport := checkReports[0]
	if gotReport.Status != "FINISHED" {
		t.Fatalf("unexpected status: %v", gotReport.Status)
	}

	if len(gotReport.Vulnerabilities) != 1 {
		t.Fatalf("unexpected number of vulnerabilities: %v", len(gotReport.Vulnerabilities))
	}

	gotDetails := gotReport.Vulnerabilities[0].Details
	if gotDetails != wantDetails {
		t.Fatalf("unexpected summary: got: %q, want: %q", gotDetails, wantDetails)
	}
}

func TestRun_docker_image(t *testing.T) {
	var (
		checktypesURLs = []string{"testdata/engine/checktypes_trivy.json"}
		targets        = []config.Target{
			{
				Identifier: "python:3.4-alpine",
				AssetType:  config.AssetType(types.DockerImage),
			},
		}
		agentConfig = config.AgentConfig{
			PullPolicy: agentconfig.PullPolicyIfNotPresent,
		}
	)

	engineReport, err := Run(checktypesURLs, targets, agentConfig)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var checkReports []report.Report
	for _, v := range engineReport {
		checkReports = append(checkReports, v)
	}

	if len(checkReports) != 1 {
		t.Fatalf("unexpected number of reports: %v", len(checkReports))
	}

	gotReport := checkReports[0]
	if gotReport.Status != "FINISHED" {
		t.Fatalf("unexpected status: %v", gotReport.Status)
	}

	if len(gotReport.Vulnerabilities) == 0 {
		t.Fatalf("no vulnerabilities found")
	}

	t.Logf("found %v vulnerabilities", len(gotReport.Vulnerabilities))
}

func TestRun_no_jobs(t *testing.T) {
	var (
		checktypesURLs = []string{"testdata/engine/checktypes_lava_engine_test.json"}
		agentConfig    = config.AgentConfig{
			PullPolicy: agentconfig.PullPolicyNever,
		}
	)

	engineReport, err := Run(checktypesURLs, nil, agentConfig)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(engineReport) != 0 {
		t.Fatalf("unexpected number of reports: %v", len(engineReport))
	}
}

func TestFixCheckTarget(t *testing.T) {
	tests := []struct {
		name       string
		target     string
		assetType  string
		want       string
		wantNilErr bool
	}{
		{
			name:       "local IP",
			target:     "127.0.0.1",
			assetType:  "IP",
			want:       dockerInternalHost,
			wantNilErr: true,
		},
		{
			name:       "remote IP",
			target:     "192.168.1.1",
			assetType:  "IP",
			want:       "192.168.1.1",
			wantNilErr: true,
		},
		{
			name:       "local Hostname",
			target:     "localhost",
			assetType:  "Hostname",
			want:       dockerInternalHost,
			wantNilErr: true,
		},
		{
			name:       "remote Hostname",
			target:     "example.com",
			assetType:  "Hostname",
			want:       "example.com",
			wantNilErr: true,
		},
		{
			name:       "local WebAddress",
			target:     "http://127.0.0.1:12345/path",
			assetType:  "WebAddress",
			want:       fmt.Sprintf("http://%v:12345/path", dockerInternalHost),
			wantNilErr: true,
		},
		{
			name:       "remote WebAddress",
			target:     "http://192.168.1.1/path",
			assetType:  "WebAddress",
			want:       "http://192.168.1.1/path",
			wantNilErr: true,
		},
		{
			name:       "local GitRepository",
			target:     "ssh://git@localhost:12345/path/to/repo.git",
			assetType:  "GitRepository",
			want:       fmt.Sprintf("ssh://git@%v:12345/path/to/repo.git", dockerInternalHost),
			wantNilErr: true,
		},
		{
			name:       "remote GitRepository",
			target:     "git@example.com:/path/to/repo.git",
			assetType:  "GitRepository",
			want:       "ssh://git@example.com/path/to/repo.git",
			wantNilErr: true,
		},
		{
			name:       "multiple host occurrences",
			target:     "localhost://localhost:12345/path",
			assetType:  "WebAddress",
			want:       fmt.Sprintf("localhost://%v:12345/path", dockerInternalHost),
			wantNilErr: true,
		},
		{
			name:       "DockerImage",
			target:     "alpine:3.18",
			assetType:  "DockerImage",
			want:       "alpine:3.18",
			wantNilErr: true,
		},
		{
			name:       "invalid GitRepository",
			target:     "ssh://git@localhost:invalidport/path/to/repo.git",
			assetType:  "GitRepository",
			want:       "",
			wantNilErr: false,
		},
		{
			name:       "invalid WebAddress",
			target:     "http://127.0.0.1:invalidport/path",
			assetType:  "WebAddress",
			want:       "",
			wantNilErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := fixCheckTarget(tt.target, tt.assetType)

			if (err == nil) != tt.wantNilErr {
				t.Errorf("unexpected error: %v", err)
			}

			if got != tt.want {
				t.Errorf("unexpected target: got: %q, want: %q", got, tt.want)
			}
		})
	}
}

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
			name: "WebAddress",
			target: config.Target{
				AssetType:  config.AssetType(types.WebAddress),
				Identifier: "https://example.com/path",
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
			want:       "github.com",
			wantNilErr: true,
		},
		{
			name: "GitRepository URL",
			target: config.Target{
				AssetType:  config.AssetType(types.GitRepository),
				Identifier: "https://example.com:443/path/to/repo.git/",
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

func dockerBuild(path, tag string) error {
	cli, err := dockerutil.NewAPIClient()
	if err != nil {
		return fmt.Errorf("new client: %w", err)
	}
	defer cli.Close()

	tar, err := archive.TarWithOptions(path, &archive.TarOptions{})
	if err != nil {
		return fmt.Errorf("new tar: %w", err)
	}

	opts := dockertypes.ImageBuildOptions{
		Tags:   []string{tag},
		Remove: true,
	}
	resp, err := cli.ImageBuild(context.Background(), tar, opts)
	if err != nil {
		return fmt.Errorf("image build: %w", err)
	}
	defer resp.Body.Close()

	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	return nil
}
