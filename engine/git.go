// Copyright 2023 Adevinta

package engine

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path"
	"strings"

	types "github.com/adevinta/vulcan-types"

	"github.com/adevinta/lava/config"
	"github.com/adevinta/lava/gitserver"
)

// updateAndServeLocalGitRepos serves the local Git repositories in
// the provided targets using the specified Git server. The
// corresponding targets are updated with the address of the Git
// server.
func updateAndServeLocalGitRepos(gs *gitserver.Server, targets []config.Target) (err error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("GitServer listener: %w", err)
	}
	defer func() {
		if err != nil {
			ln.Close()
		}
	}()

	for i, t := range targets {
		if t.AssetType != config.AssetType(types.GitRepository) {
			continue
		}
		info, err := os.Stat(t.Identifier)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return fmt.Errorf("stat repository path: %w", err)
		}
		if !info.IsDir() {
			return errors.New("local Git repository must be a directory")
		}
		repo, err := gs.AddRepository(t.Identifier)
		if err != nil {
			return fmt.Errorf("add Git repository: %w", err)
		}
		targets[i].Identifier = fmt.Sprintf("http://%v/%v", ln.Addr(), repo)
	}

	go gs.Serve(ln) //nolint:errcheck

	return nil
}

// parseGitURL parses a Git URL. If s is a scp-like Git URL, it is
// first converted into a SSH URL.
func parseGitURL(gitURL string) (*url.URL, error) {
	rawURL := gitURL
	if !strings.Contains(gitURL, "://") {
		// scp-like syntax is only recognized if there are no
		// slashes before the first colon.
		cidx := strings.Index(gitURL, ":")
		sidx := strings.Index(gitURL, "/")
		if cidx >= 0 && (sidx < 0 || cidx < sidx) {
			rawURL = "ssh://" + gitURL[:cidx] + path.Join("/", gitURL[cidx+1:])
		}
	}
	return url.Parse(rawURL)
}
