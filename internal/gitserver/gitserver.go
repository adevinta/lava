// Copyright 2023 Adevinta

// Package gitserver provides a read-only smart HTTP Git server.
package gitserver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sync"
)

// ErrGit is returned by [New] when the git command cannot be run.
var ErrGit = errors.New("git cannot be run")

// Server represents a Git server.
type Server struct {
	basePath string
	httpsrv  *http.Server

	mu    sync.Mutex
	repos map[string]string
	paths map[string]string
}

// New creates a git server, but doesn't start it.
func New() (*Server, error) {
	if err := checkGit(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGit, err)
	}

	tmpPath, err := os.MkdirTemp("", "")
	if err != nil {
		return nil, fmt.Errorf("make temp dir: %w", err)
	}

	srv := &Server{
		basePath: tmpPath,
		repos:    make(map[string]string),
		paths:    make(map[string]string),
		httpsrv:  &http.Server{Handler: newSmartServer(tmpPath)},
	}
	return srv, nil
}

// AddRepository adds a repository to the Git server. It returns the
// name of the new served repository.
func (srv *Server) AddRepository(path string) (string, error) {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	if repoName, ok := srv.repos[path]; ok {
		return repoName, nil
	}

	dstPath, err := os.MkdirTemp(srv.basePath, "*.git")
	if err != nil {
		return "", fmt.Errorf("make temp dir: %w", err)
	}

	// --mirror implies --bare. Compared to --bare, --mirror not
	// only maps local branches of the source to local branches of
	// the target, it maps all refs (including remote-tracking
	// branches, notes etc.) and sets up a refspec configuration
	// such that all these refs are overwritten by a git remote
	// update in the target repository.
	cmd := exec.Command("git", "clone", "--mirror", path, dstPath)
	if err = cmd.Run(); err != nil {
		return "", fmt.Errorf("git clone: %w", err)
	}

	// Create a branch at HEAD. So, if HEAD is detached, the Git
	// client is able to guess the reference where HEAD is
	// pointing to.
	//
	// Reference: https://github.com/go-git/go-git/blob/f92cb0d49088af996433ebb106b9fc7c2adb8875/plumbing/protocol/packp/advrefs.go#L94-L104
	branch := fmt.Sprintf("lava-%v", rand.Int63())
	cmd = exec.Command("git", "branch", branch)
	cmd.Dir = dstPath
	if err = cmd.Run(); err != nil {
		return "", fmt.Errorf("git branch: %w", err)
	}

	repoName := filepath.Base(dstPath)
	srv.repos[path] = repoName
	return repoName, nil
}

// AddPath adds a file path to the Git server. The path is served as a
// Git repository with a single commit. It returns the name of the new
// served repository.
func (srv *Server) AddPath(path string) (string, error) {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	if repoName, ok := srv.paths[path]; ok {
		return repoName, nil
	}

	dstPath, err := os.MkdirTemp(srv.basePath, "*.git")
	if err != nil {
		return "", fmt.Errorf("make temp dir: %w", err)
	}

	if err := fscopy(dstPath, path); err != nil {
		return "", fmt.Errorf("copy files: %w", err)
	}

	cmd := exec.Command("git", "init")
	cmd.Dir = dstPath
	if err = cmd.Run(); err != nil {
		return "", fmt.Errorf("git init: %w", err)
	}

	cmd = exec.Command("git", "add", "-f", ".")
	cmd.Dir = dstPath
	if err = cmd.Run(); err != nil {
		return "", fmt.Errorf("git add: %w", err)
	}

	cmd = exec.Command(
		"git",
		"-c", "user.name=lava",
		"-c", "user.email=lava@lava.local",
		"commit", "-m", "[auto] lava",
	)
	cmd.Dir = dstPath
	if err = cmd.Run(); err != nil {
		return "", fmt.Errorf("git commit: %w", err)
	}

	repoName := filepath.Base(dstPath)
	srv.paths[path] = repoName
	return repoName, nil
}

// fscopy copies src to dst recursively. It ignores all .git
// files and directories.
func fscopy(dst, src string) error {
	err := filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(src, path)
		if err != nil {
			return fmt.Errorf("rel: %w", err)
		}

		switch typ := d.Type(); {
		case typ.IsDir():
			if rel == "." {
				// The source path is a directory. The
				// destination directory already
				// exists, so it is not necessary to
				// create it.
				return nil
			}
			if filepath.Base(rel) == ".git" {
				// Ignore .git directory.
				return filepath.SkipDir
			}
			if err := os.MkdirAll(filepath.Join(dst, rel), 0755); err != nil {
				return fmt.Errorf("make dir: %w", err)
			}
		case typ.IsRegular():
			if rel == "." {
				// The source path is a file. The
				// destination file is the name of the
				// source file.
				rel = filepath.Base(path)
			}

			if filepath.Base(rel) == ".git" {
				// Ignore .git file. This file is
				// present in the case of git
				// submodules.
				return nil
			}

			fsrc, err := os.Open(path)
			if err != nil {
				return fmt.Errorf("open source file: %w", err)
			}
			defer fsrc.Close()
			fdst, err := os.Create(filepath.Join(dst, rel))
			if err != nil {
				return fmt.Errorf("create destination file: %w", err)
			}
			defer fdst.Close()
			if _, err := io.Copy(fdst, fsrc); err != nil {
				return fmt.Errorf("copy file: %w", err)
			}
		default:
			slog.Warn("invalid file type", "path", path, "mode", typ)
		}
		return nil
	})

	if err != nil {
		return fmt.Errorf("walk dir: %w", err)
	}
	return nil
}

// ListenAndServe listens on the TCP network address addr and then
// calls [*GitServer.Serve] to handle requests on incoming
// connections.
//
// ListenAndServe always returns a non-nil error.
func (srv *Server) ListenAndServe(addr string) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	return srv.Serve(l)
}

// testHookServerServe is executed at the beginning of
// [*GitServer.Serve] if not nil. It is set by tests.
var testHookServerServe func(*Server, net.Listener)

// Serve accepts incoming connections on the [http.Listener] l.
//
// Serve always returns a non-nil error and closes l.
func (srv *Server) Serve(l net.Listener) error {
	if fn := testHookServerServe; fn != nil {
		fn(srv, l)
	}
	return srv.httpsrv.Serve(l)
}

// Close stops the server and deletes any temporary directory created
// to store the repositories.
func (srv *Server) Close() error {
	if err := srv.httpsrv.Shutdown(context.Background()); err != nil {
		return fmt.Errorf("server shutdown: %w", err)
	}
	if err := os.RemoveAll(srv.basePath); err != nil {
		return fmt.Errorf("remove temp dirs: %w", err)
	}
	return nil
}

// checkGit checks that the git command can be run.
func checkGit() error {
	return exec.Command("git", "version").Run()
}

// smartServer provides a read-only smart HTTP Git protocol
// implementation.
type smartServer struct {
	basePath string
}

// newSmartServer returns a new [smartServer]. Served repositories are
// relative to basePath.
func newSmartServer(basePath string) *smartServer {
	return &smartServer{basePath: basePath}
}

// pathRE is used to parse HTTP requests.
var pathRE = regexp.MustCompile(`^(/.*?)(/.*)$`)

// ServeHTTP implements the smart server router.
func (srv *smartServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	matches := pathRE.FindStringSubmatch(path.Clean(r.URL.Path))
	if matches == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	repo := matches[1]
	endpoint := matches[2]

	switch endpoint {
	case "/info/refs":
		srv.handleInfoRefs(w, r, repo)
	case "/git-upload-pack":
		srv.handleGitUploadPack(w, r, repo)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// handleInfoRefs handles requests to /repo/info/refs.
func (srv *smartServer) handleInfoRefs(w http.ResponseWriter, r *http.Request, repo string) {
	if r.Method != "GET" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	if r.URL.Query().Get("service") != "git-upload-pack" {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	buf := &bytes.Buffer{}
	repoPath := filepath.Join(srv.basePath, repo)
	cmd := exec.Command("git-upload-pack", "--advertise-refs", repoPath)
	cmd.Stdout = buf
	if err := cmd.Run(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")

	pkt := "# service=git-upload-pack\n"
	fmt.Fprintf(w, "%04x%v0000%v", len(pkt)+4, pkt, buf)
}

// handleGitUploadPack handles requests to /repo/git-upload-pack.
func (srv *smartServer) handleGitUploadPack(w http.ResponseWriter, r *http.Request, repo string) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	buf := &bytes.Buffer{}
	repoPath := filepath.Join(srv.basePath, repo)
	cmd := exec.Command("git-upload-pack", "--stateless-rpc", repoPath)
	cmd.Stdin = r.Body
	cmd.Stdout = buf
	if err := cmd.Run(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/x-git-upload-pack-result")
	fmt.Fprintf(w, "%v", buf)
}
