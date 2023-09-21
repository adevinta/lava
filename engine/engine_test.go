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
	"path/filepath"
	"testing"

	agentconfig "github.com/adevinta/vulcan-agent/config"
	report "github.com/adevinta/vulcan-report"
	types "github.com/adevinta/vulcan-types"
	dockertypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/pkg/archive"

	"github.com/adevinta/lava/config"
	"github.com/adevinta/lava/dockerutil"
	"github.com/adevinta/lava/gitserver/gittest"
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
			PullPolicy: agentconfig.PullPolicyAlways,
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

func TestRun_git_repository(t *testing.T) {
	var (
		checktypesURLs = []string{"testdata/engine/checktypes_trivy.json"}
		agentConfig    = config.AgentConfig{
			PullPolicy: agentconfig.PullPolicyAlways,
		}
	)

	tmpPath, err := gittest.ExtractTemp("testdata/engine/vulnrepo.tar")
	if err != nil {
		t.Fatalf("unexpected error extracting test repository: %v", err)
	}
	defer os.RemoveAll(tmpPath)

	tests := []struct {
		name       string
		target     config.Target
		wantErr    bool
		wantStatus string
		wantVulns  bool
	}{
		{
			name: "dir",
			target: config.Target{
				Identifier: tmpPath,
				AssetType:  config.AssetType(types.GitRepository),
			},
			wantErr:    false,
			wantStatus: "FINISHED",
			wantVulns:  true,
		},
		{
			name: "file",
			target: config.Target{
				Identifier: filepath.Join(tmpPath, "Dockerfile"),
				AssetType:  config.AssetType(types.GitRepository),
			},
			wantErr: true,
		},
		{
			name: "not exist",
			target: config.Target{
				Identifier: filepath.Join(tmpPath, "notexist"),
				AssetType:  config.AssetType(types.GitRepository),
			},
			wantErr:    false,
			wantStatus: "INCONCLUSIVE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engineReport, err := Run(checktypesURLs, []config.Target{tt.target}, agentConfig)
			if err != nil {
				if !tt.wantErr {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}

			var checkReports []report.Report
			for _, v := range engineReport {
				checkReports = append(checkReports, v)
			}

			if len(checkReports) != 1 {
				t.Fatalf("unexpected number of reports: %v", len(checkReports))
			}

			gotReport := checkReports[0]
			if gotReport.Status != tt.wantStatus {
				t.Fatalf("unexpected status: %v", gotReport.Status)
			}

			if (len(gotReport.Vulnerabilities) > 0) != tt.wantVulns {
				t.Fatalf("unexpected number of vulnerabilities: %v", len(gotReport.Vulnerabilities))
			}

			t.Logf("found %v vulnerabilities", len(gotReport.Vulnerabilities))
		})
	}
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
