// Copyright 2024 Adevinta

package run

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"testing"

	agentconfig "github.com/adevinta/vulcan-agent/config"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/jroimartin/clilog"

	"github.com/adevinta/lava/internal/containers"
	"github.com/adevinta/lava/internal/report"
)

const checktype = "vulcansec/vulcan-gitleaks:ea42ea5-b6abd8a"

var testRuntime containers.Runtime

func TestMain(m *testing.M) {
	flag.Parse()

	level := slog.LevelError
	if testing.Verbose() {
		level = slog.LevelDebug
	}

	h := clilog.NewCLIHandler(os.Stderr, &clilog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(h))

	rt, err := containers.GetenvRuntime()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: get env runtime: %v", err)
		os.Exit(2)
	}
	testRuntime = rt

	os.Exit(m.Run())
}

func TestRunRun(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		wantExitCode int
	}{
		{
			name:         "good path",
			path:         "testdata/goodpath",
			wantExitCode: 0,
		},
		{
			name:         "vulnerable path",
			path:         "testdata/vulnpath",
			wantExitCode: 103,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldPwd := mustGetwd()
			oldOsExit := osExit
			oldRunO := runO
			oldRunOptfile := runOptfile
			defer func() {
				mustChdir(oldPwd)
				osExit = oldOsExit
				runO = oldRunO
				runOptfile = oldRunOptfile
			}()

			runO = "output.txt"
			runOptfile = "options.json"

			var exitCode int
			osExit = func(status int) {
				exitCode = status
			}

			mustChdir(tt.path)
			if err := runRun([]string{checktype, "."}); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if exitCode != tt.wantExitCode {
				t.Errorf("unexpected exit code: got: %v, want: %v", exitCode, tt.wantExitCode)
			}
		})
	}
}

func TestRunRun_path_checktype(t *testing.T) {
	oldPwd := mustGetwd()
	oldOsExit := osExit
	oldRunO := runO
	defer func() {
		mustChdir(oldPwd)
		osExit = oldOsExit
		runO = oldRunO
	}()

	runO = "output.txt"

	var exitCode int
	osExit = func(status int) {
		exitCode = status
	}

	cli, err := containers.NewDockerdClient(testRuntime)
	if err != nil {
		t.Fatalf("could not create dockerd client: %v", err)
	}
	defer cli.Close()

	mustChdir("testdata/lava-run-test")
	if err := runRun([]string{".", "."}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() {
		const imgRef = "lava-run-test:lava-run"
		rmOpts := image.RemoveOptions{Force: true, PruneChildren: true}
		if _, err := cli.ImageRemove(context.Background(), imgRef, rmOpts); err != nil {
			t.Logf("could not delete test Docker image %q: %v", imgRef, err)
		}
	}()

	if exitCode != int(report.ExitCodeCritical) {
		t.Errorf("unexpected exit code: %v", exitCode)
	}
}

func TestRunRun_path_checktype_same_id(t *testing.T) {
	oldPwd := mustGetwd()
	oldOsExit := osExit
	oldRunO := runO
	oldPull := runPull
	defer func() {
		mustChdir(oldPwd)
		osExit = oldOsExit
		runO = oldRunO
		runPull = oldPull
	}()

	runO = "output.txt"
	runPull = agentconfig.PullPolicyNever

	var exitCode int
	osExit = func(status int) {
		exitCode = status
	}

	cli, err := containers.NewDockerdClient(testRuntime)
	if err != nil {
		t.Fatalf("could not create dockerd client: %v", err)
	}
	defer cli.Close()

	mustChdir("testdata/lava-run-test")

	const ref = "lava-run-test:lava-run"

	defer func() {
		rmOpts := image.RemoveOptions{Force: true, PruneChildren: true}
		if _, err := cli.ImageRemove(context.Background(), ref, rmOpts); err != nil {
			t.Logf("could not delete test Docker image %q: %v", ref, err)
		}
	}()

	var ids [2]string
	for i := 0; i < 2; i++ {
		exitCode = 0
		if err := runRun([]string{".", "."}); err != nil {
			t.Fatalf("unexpected error in run %v: %v", i, err)
		}
		if exitCode != int(report.ExitCodeCritical) {
			t.Errorf("unexpected exit code in run %v: %v", i, exitCode)
		}

		summ, err := cli.ImageList(context.Background(), image.ListOptions{
			Filters: filters.NewArgs(filters.Arg("reference", ref)),
		})
		if err != nil {
			t.Fatalf("could not get image details in run %v: %v", i, err)
		}
		if len(summ) != 1 {
			t.Fatalf("wrong number of images in run %v: %v", i, err)
		}
		ids[i] = summ[0].ID
	}

	if ids[0] != ids[1] {
		t.Errorf("image IDs do not match: %q != %q", ids[0], ids[1])
	}
}

// mustGetwd returns a rooted path name corresponding to the current
// directory. It panics on error.
func mustGetwd() string {
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	return wd
}

// mustChdir changes the current working directory to the named
// directory. It panics on error.
func mustChdir(path string) {
	if err := os.Chdir(path); err != nil {
		panic(err)
	}
}
