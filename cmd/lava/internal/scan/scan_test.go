// Copyright 2023 Adevinta

package scan

import (
	"flag"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/jroimartin/clilog"

	"github.com/adevinta/lava/internal/gitserver/gittest"
)

func TestMain(m *testing.M) {
	flag.Parse()

	level := slog.LevelError
	if testing.Verbose() {
		level = slog.LevelDebug
	}

	h := clilog.NewCLIHandler(os.Stderr, &clilog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(h))

	os.Exit(m.Run())
}

func TestRun(t *testing.T) {
	tests := []struct {
		name         string
		wantExitCode int
		repo         string
	}{
		{
			name:         "good repo",
			wantExitCode: 0,
			repo:         "testdata/goodrepo.tar",
		},
		{
			name:         "vulnerable repo",
			wantExitCode: 103,
			repo:         "testdata/vulnrepo.tar",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldPwd := mustGetwd()
			oldCfgfile := *cfgfile
			oldOsExit := osExit
			defer func() {
				mustChdir(oldPwd)
				*cfgfile = oldCfgfile
				osExit = oldOsExit
			}()

			tmpPath, err := gittest.ExtractTemp(tt.repo)
			if err != nil {
				t.Fatalf("unexpected error extracting test repository: %v", err)
			}
			defer os.RemoveAll(tmpPath)

			*cfgfile = filepath.Join(tmpPath, "lava.yaml")

			var exitCode int
			osExit = func(status int) {
				exitCode = status
			}

			mustChdir(tmpPath)
			if err := run(nil); err != nil {
				t.Fatalf("run error: %v", err)
			}

			if exitCode != tt.wantExitCode {
				t.Errorf("unexpected exit code: got: %v, want: %v", exitCode, tt.wantExitCode)
			}
		})
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
