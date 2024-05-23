// Copyright 2023 Adevinta

package gitserver

import (
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
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

func TestServer_AddRepository(t *testing.T) {
	// Not parallel: uses global test hook.
	defer func() { testHookServerServe = nil }()

	tmpPath, err := gittest.ExtractTemp("testdata/repo.tar")
	if err != nil {
		t.Fatalf("unable to create a repository: %v", err)
	}
	defer os.RemoveAll(tmpPath)

	gs, err := New()
	if err != nil {
		t.Fatalf("unable to create a server: %v", err)
	}
	defer gs.Close()

	lnc := make(chan net.Listener)
	testHookServerServe = func(gs *Server, ln net.Listener) {
		lnc <- ln
	}

	go gs.ListenAndServe("127.0.0.1:0") //nolint:errcheck

	ln := <-lnc

	repoName, err := gs.AddRepository(tmpPath)
	if err != nil {
		t.Fatalf("unable to add a repository: %v", err)
	}

	repoPath, err := gittest.CloneTemp(fmt.Sprintf("http://%v/%s", ln.Addr(), repoName))
	if err != nil {
		t.Fatalf("unable to clone the repo %s: %v", repoName, err)
	}
	defer os.RemoveAll(repoPath)

	if _, err := os.Stat(filepath.Join(repoPath, "foo.txt")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestServer_AddRepository_no_repo(t *testing.T) {
	tmpPath, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("unable to create a temporary dir")
	}
	defer os.RemoveAll(tmpPath)

	gs, err := New()
	if err != nil {
		t.Fatalf("unable to create a server: %v", err)
	}
	defer gs.Close() //nolint:staticcheck

	if _, err = gs.AddRepository(tmpPath); err == nil {
		t.Fatal("expected error adding repository")
	}
}

func TestServer_AddRepository_invalid_dir(t *testing.T) {
	gs, err := New()
	if err != nil {
		t.Fatalf("unable to create a server: %v", err)
	}
	defer gs.Close() //nolint:staticcheck

	if _, err = gs.AddRepository("/fakedir"); err == nil {
		t.Fatal("expected error adding repository")
	}
}

func TestServer_AddRepository_invalid_dir_2(t *testing.T) {
	tmpPath, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("unable to create a temporary dir")
	}
	defer os.RemoveAll(tmpPath)

	gs := &Server{
		basePath: "testdata/fakedir",
		repos:    make(map[string]string),
		httpsrv:  &http.Server{Handler: newSmartServer(tmpPath)},
	}
	defer gs.Close() //nolint:staticcheck

	if _, err = gs.AddRepository(tmpPath); err == nil {
		t.Fatal("expected error adding repository")
	}
}

func TestServer_AddRepository_do_not_cache_error(t *testing.T) {
	gs, err := New()
	if err != nil {
		t.Fatalf("unable to create a server: %v", err)
	}
	defer gs.Close() //nolint:staticcheck

	if _, err = gs.AddRepository("/fakedir"); err == nil {
		t.Fatal("expected error adding repository")
	}

	if _, err = gs.AddRepository("/fakedir"); err == nil {
		t.Fatal("expected error adding repository")
	}
}

func TestServer_AddRepository_already_added(t *testing.T) {
	tmpPath, err := gittest.ExtractTemp("testdata/repo.tar")
	if err != nil {
		t.Fatalf("unable to create a repository: %v", err)
	}
	defer os.RemoveAll(tmpPath)

	gs, err := New()
	if err != nil {
		t.Fatalf("unable to create a server: %v", err)
	}
	defer gs.Close()

	repoName, err := gs.AddRepository(tmpPath)
	if err != nil {
		t.Fatalf("unable to add a repository: %v", err)
	}
	repoName2, err := gs.AddRepository(tmpPath)
	if err != nil {
		t.Fatalf("unable to add a repository: %v", err)
	}

	if repoName != repoName2 {
		t.Fatalf("%s should be the same as %s", repoName, repoName2)
	}
}

func TestServer_AddPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{
			name: "dir",
			path: "testdata/dir",
			want: "foo.txt",
		},
		{
			name: "file",
			path: "testdata/dir/foo.txt",
			want: "foo.txt",
		},
		{
			name: "symlink",
			path: "testdata/symlink",
			want: "bar.txt",
		},
		{
			name: "repo",
			path: "testdata/repo.tar",
			want: "foo.txt",
		},
		{
			name: "submodule",
			path: "testdata/submodule.tar",
			want: "foo.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Not parallel: uses global test hook.
			defer func() { testHookServerServe = nil }()

			path := tt.path
			if filepath.Ext(tt.path) == ".tar" {
				tmpPath, err := gittest.ExtractTemp(tt.path)
				if err != nil {
					t.Fatalf("unable to create a repository: %v", err)
				}
				defer os.RemoveAll(tmpPath)

				path = tmpPath
			}

			gs, err := New()
			if err != nil {
				t.Fatalf("unable to create a server: %v", err)
			}
			defer gs.Close()

			lnc := make(chan net.Listener)
			testHookServerServe = func(gs *Server, ln net.Listener) {
				lnc <- ln
			}

			go gs.ListenAndServe("127.0.0.1:0") //nolint:errcheck

			ln := <-lnc

			repoName, err := gs.AddPath(path)
			if err != nil {
				t.Fatalf("unable to add a path: %v", err)
			}

			repoPath, err := gittest.CloneTemp(fmt.Sprintf("http://%v/%s", ln.Addr(), repoName))
			if err != nil {
				t.Fatalf("unable to clone the repo %s: %v", repoName, err)
			}
			defer os.RemoveAll(repoPath)

			if _, err := os.Stat(filepath.Join(repoPath, tt.want)); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestServer_AddPath_invalid_path(t *testing.T) {
	gs, err := New()
	if err != nil {
		t.Fatalf("unable to create a server: %v", err)
	}
	defer gs.Close() //nolint:staticcheck

	if _, err = gs.AddPath("/fakedir"); err == nil {
		t.Fatal("expected error adding path")
	}
}

func TestServer_AddPath_do_not_cache_error(t *testing.T) {
	gs, err := New()
	if err != nil {
		t.Fatalf("unable to create a server: %v", err)
	}
	defer gs.Close() //nolint:staticcheck

	if _, err = gs.AddPath("/fakedir"); err == nil {
		t.Fatal("expected error adding path")
	}

	if _, err = gs.AddPath("/fakedir"); err == nil {
		t.Fatal("expected error adding path")
	}
}

func TestServer_AddPath_already_added(t *testing.T) {
	gs, err := New()
	if err != nil {
		t.Fatalf("unable to create a server: %v", err)
	}
	defer gs.Close()

	repoName, err := gs.AddPath("testdata/dir")
	if err != nil {
		t.Fatalf("unable to add a path: %v", err)
	}

	repoName2, err := gs.AddPath("testdata/dir")
	if err != nil {
		t.Fatalf("unable to add a path: %v", err)
	}

	if repoName != repoName2 {
		t.Fatalf("%s should be the same as %s", repoName, repoName2)
	}
}
