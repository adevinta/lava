// Copyright 2024 Adevinta

package run

import (
	"flag"
	"log/slog"
	"os"
	"testing"

	"github.com/jroimartin/clilog"
)

const checktype = "vulcansec/vulcan-gitleaks:ea42ea5-b6abd8a"

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
