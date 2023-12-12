// Copyright 2023 Adevinta

package scan

import (
	"flag"
	"log/slog"
	"os"
	"testing"

	"github.com/jroimartin/clilog"
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
		path         string
	}{
		{
			name:         "good path",
			wantExitCode: 0,
			path:         "testdata/goodpath",
		},
		{
			name:         "vulnerable path",
			wantExitCode: 103,
			path:         "testdata/vulnpath",
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

			*cfgfile = "lava.yaml"

			var exitCode int
			osExit = func(status int) {
				exitCode = status
			}

			mustChdir(tt.path)
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
