// Copyright 2023 Adevinta

package gitserver

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/adevinta/lava/internal/gitserver/gittest"
)

func TestServer_AddRepository(t *testing.T) {
	// Not parallel: uses global test hook.
	defer func() { testHookServerServe = nil }()

	path, err := gittest.ExtractTemp(filepath.Join("testdata", "testrepo.tar"))
	if err != nil {
		t.Fatalf("unable to create a repository: %v", err)
	}
	defer os.RemoveAll(path)

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

	repoName, err := gs.AddRepository(path)
	if err != nil {
		t.Fatalf("unable to add a repository : %v", err)
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
		t.Fatal("expected error adding a repository")
	}
}

func TestServer_AddRepository_invalid_dir(t *testing.T) {
	tmpPath := "/fakedir"

	gs, err := New()
	if err != nil {
		t.Fatalf("unable to create a server: %v", err)
	}
	defer gs.Close() //nolint:staticcheck

	if _, err = gs.AddRepository(tmpPath); err == nil {
		t.Fatal("expected error adding a repository")
	}
}

func TestServer_AddRepository_invalid_dir_2(t *testing.T) {
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

	gs.basePath = "/fakedir"
	if _, err = gs.AddRepository(tmpPath); err == nil {
		t.Fatal("expected error adding a repository")
	}
}

func TestServer_AddRepository_already_added(t *testing.T) {
	path, err := gittest.ExtractTemp(filepath.Join("testdata", "testrepo.tar"))
	if err != nil {
		t.Fatalf("unable to create a repository: %v", err)
	}
	defer os.RemoveAll(path)

	gs, err := New()
	if err != nil {
		t.Fatalf("unable to create a server: %v", err)
	}
	defer gs.Close()

	repoName, err := gs.AddRepository(path)
	if err != nil {
		t.Fatalf("unable to add a repository : %v", err)
	}
	repoName2, err := gs.AddRepository(path)
	if err != nil {
		t.Fatalf("unable to add a repository : %v", err)
	}

	if repoName != repoName2 {
		t.Fatalf("%s should be the same as %s", repoName, repoName2)
	}
}
