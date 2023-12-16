// Copyright 2023 Adevinta

package scan

import (
	"flag"
	"log/slog"
	"os"
	"runtime/debug"
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
		path         string
		version      string
		wantNilErr   bool
		wantExitCode int
	}{
		{
			name:         "good path",
			path:         "testdata/goodpath",
			version:      "v1.0.0",
			wantNilErr:   true,
			wantExitCode: 0,
		},
		{
			name:         "vulnerable path",
			path:         "testdata/vulnpath",
			version:      "v1.0.0",
			wantNilErr:   true,
			wantExitCode: 103,
		},
		{
			name:       "incompatible",
			path:       "testdata/vulnpath",
			version:    "v0.1.0",
			wantNilErr: false,
		},
		{
			name:         "skip compatibility check",
			path:         "testdata/vulnpath",
			version:      "(devel)",
			wantNilErr:   true,
			wantExitCode: 103,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldPwd := mustGetwd()
			oldCfgfile := *cfgfile
			oldOsExit := osExit
			oldDebugReadBuildInfo := debugReadBuildInfo
			defer func() {
				mustChdir(oldPwd)
				*cfgfile = oldCfgfile
				osExit = oldOsExit
				debugReadBuildInfo = oldDebugReadBuildInfo
			}()

			*cfgfile = "lava.yaml"

			var exitCode int
			osExit = func(status int) {
				exitCode = status
			}

			debugReadBuildInfo = func() (*debug.BuildInfo, bool) {
				bi := &debug.BuildInfo{
					Main: debug.Module{
						Version: tt.version,
					},
				}
				return bi, true
			}

			mustChdir(tt.path)
			if err := run(nil); (err == nil) != tt.wantNilErr {
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
