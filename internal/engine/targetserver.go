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
	"strconv"
	"strings"
	"sync"
	"syscall"

	types "github.com/adevinta/vulcan-types"
	"github.com/jroimartin/proxy"

	"github.com/adevinta/lava/internal/assettype"
	"github.com/adevinta/lava/internal/config"
	"github.com/adevinta/lava/internal/gitserver"
)

// targetMap maps a target identifier with its updated value.
type targetMap struct {
	// OldIdentifier is the original target identifier.
	OldIdentifier string

	// OldAssetType is the original asset type of the target.
	OldAssetType types.AssetType

	// NewIdentifier is the updated target identifier.
	NewIdentifier string

	// NewAssetType is the updated asset type of the target.
	NewAssetType types.AssetType
}

// IsZero reports whether tm is the zero value.
func (tm targetMap) IsZero() bool {
	return tm == targetMap{}
}

// Addrs returns a [targetMap] with the addresses of the targets. If
// it is not possible to get the address of a target, then the target
// is used.
func (tm targetMap) Addrs() targetMap {
	oldAddr, err := getTargetAddr(config.Target{Identifier: tm.OldIdentifier, AssetType: tm.OldAssetType})
	if err != nil {
		oldAddr = tm.OldIdentifier
	}

	newAddr, err := getTargetAddr(config.Target{Identifier: tm.NewIdentifier, AssetType: tm.NewAssetType})
	if err != nil {
		newAddr = tm.NewIdentifier
	}

	tmAddrs := targetMap{
		OldIdentifier: oldAddr,
		OldAssetType:  tm.OldAssetType,
		NewIdentifier: newAddr,
		NewAssetType:  tm.NewAssetType,
	}
	return tmAddrs
}

// targetServer represents Lava's internal target server. It is used
// to serve local Git repositories and services.
type targetServer struct {
	gs      *gitserver.Server
	gitAddr string
	pg      *proxy.Group

	mu   sync.Mutex
	maps map[string]targetMap
}

// newTargetServer returns a new [targetServer].
func newTargetServer() (srv *targetServer, err error) {
	gs, err := gitserver.New()
	if err != nil {
		return nil, fmt.Errorf("new GitServer: %w", err)
	}

	listenHost, err := bridgeHost()
	if err != nil {
		return nil, fmt.Errorf("get bridge host: %w", err)
	}

	ln, err := net.Listen("tcp", net.JoinHostPort(listenHost, "0"))
	if err != nil {
		return nil, fmt.Errorf("GitServer listener: %w", err)
	}

	_, gitPort, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		return nil, fmt.Errorf("split Git server host port: %w", err)
	}

	go gs.Serve(ln) //nolint:errcheck

	srv = &targetServer{
		gs:      gs,
		gitAddr: net.JoinHostPort(dockerInternalHost, gitPort),
		pg:      proxy.NewGroup(),
		maps:    make(map[string]targetMap),
	}
	return srv, nil
}

// Handle handles the provided target. If the target is a local Git
// repository (i.e. a directory in the Host), it is served using
// Lava's internal Git server. If the target is a local service, it is
// served through an internal proxy, so Vulcan checks can access the
// service. The specified key should be unique and it is used to index
// the generated target maps. If the key is known, the cached
// [targetMap] is returned. The returned [targetMap] is the zero value
// if it is not necessary to map the target.
func (srv *targetServer) Handle(key string, target config.Target) (targetMap, error) {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	if tm, ok := srv.maps[key]; ok {
		return tm, nil
	}

	var (
		tm  targetMap
		err error
	)
	switch target.AssetType {
	case types.GitRepository:
		tm, err = srv.handleGitRepo(target)
	case assettype.Path:
		tm, err = srv.handlePath(target)
	default:
		tm, err = srv.handle(target)
	}
	if err != nil {
		return targetMap{}, err
	}

	if !tm.IsZero() {
		srv.maps[key] = tm
	}
	return tm, err
}

// handle serves the specified target through an internal proxy, so
// Vulcan checks can access the service.
func (srv *targetServer) handle(target config.Target) (targetMap, error) {
	stream, loopback, err := mkStream(target)
	if err != nil {
		return targetMap{}, fmt.Errorf("generate stream: %w", err)
	}

	if !loopback {
		return targetMap{}, errors.New("not a loopback address")
	}

	batch := srv.pg.ListenAndServe(stream)
	defer func() {
		// Discard remaining events and errors. So
		// *proxy.Group.Close can free resources.
		go batch.Flush()
	}()

loop:
	for {
		select {
		case err, ok := <-batch.Errors():
			// No listeners.
			if !ok {
				break loop
			}

			// If there is a service already listening on
			// that address, then assume that it is the
			// target service and ignore the error.
			if errors.Is(err, syscall.EADDRINUSE) {
				break loop
			}

			// An unexpected error happened in one of the
			// proxies.
			return targetMap{}, fmt.Errorf("proxy group: %w", err)
		case ev := <-batch.Events():
			if ev.Kind == proxy.KindBeforeAccept {
				// The proxy is listening.
				break loop
			}
		}
	}

	intIdentifier, err := mkIntIdentifier(target)
	if err != nil {
		return targetMap{}, fmt.Errorf("generate internal identifier: %w", err)
	}

	tm := targetMap{
		OldIdentifier: target.Identifier,
		OldAssetType:  target.AssetType,
		NewIdentifier: intIdentifier,
		NewAssetType:  target.AssetType,
	}
	return tm, nil
}

// handleGitRepo serves the provided Git repository using Lava's
// internal Git server.
func (srv *targetServer) handleGitRepo(target config.Target) (targetMap, error) {
	info, err := os.Stat(target.Identifier)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// If the path does not exist, assume that the
			// target is a remote Git repository.
			return targetMap{}, nil
		}
		return targetMap{}, fmt.Errorf("stat repository path: %w", err)
	}

	if !info.IsDir() {
		// If the path does not point to a directory, do not
		// handle the Git repository.
		return targetMap{}, nil
	}

	repo, err := srv.gs.AddRepository(target.Identifier)
	if err != nil {
		return targetMap{}, fmt.Errorf("add Git repository: %w", err)
	}

	tm := targetMap{
		OldIdentifier: target.Identifier,
		OldAssetType:  target.AssetType,
		NewIdentifier: fmt.Sprintf("http://%v/%v", srv.gitAddr, repo),
		NewAssetType:  target.AssetType,
	}
	return tm, nil
}

// handlePath serves the provided path as a Git repository with a
// single commit.
func (srv *targetServer) handlePath(target config.Target) (targetMap, error) {
	repo, err := srv.gs.AddPath(target.Identifier)
	if err != nil {
		return targetMap{}, fmt.Errorf("add path: %w", err)
	}

	tm := targetMap{
		OldIdentifier: target.Identifier,
		OldAssetType:  target.AssetType,
		NewIdentifier: fmt.Sprintf("http://%v/%v", srv.gitAddr, repo),
		NewAssetType:  assettype.ToVulcan(target.AssetType),
	}
	return tm, nil
}

// TargetMap returns the target map corresponding to the specified
// key. If the target map cannot be found, the returned [targetMap] is
// the zero value and the boolean is false.
func (srv *targetServer) TargetMap(key string) (tm targetMap, ok bool) {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	tm, ok = srv.maps[key]
	return
}

// Close closes the internal Git server and proxy.
func (srv *targetServer) Close() error {
	if err := srv.gs.Close(); err != nil {
		return fmt.Errorf("close Git server: %w", err)
	}

	if err := srv.pg.Close(); err != nil {
		return fmt.Errorf("close proxy group: %w", err)
	}

	return nil
}

// mkStream generates a [proxy.Stream] between the Docker bridge
// network and the provided target. It uses the same port as the
// address, so if the target is host:port, the returned stream will be
// "bridgehost:port,host:port". The returned bool reports whether the
// target is a loopback address.
func mkStream(target config.Target) (stream proxy.Stream, loopback bool, err error) {
	addr, err := getTargetAddr(target)
	if err != nil {
		return proxy.Stream{}, false, fmt.Errorf("get target addr: %w", err)
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return proxy.Stream{}, false, fmt.Errorf("split host port: %w", err)
	}

	listenHost, err := bridgeHost()
	if err != nil {
		return proxy.Stream{}, false, fmt.Errorf("get listen host: %w", err)
	}

	listenAddr := net.JoinHostPort(listenHost, port)
	dialAddr := net.JoinHostPort(host, port)
	s := fmt.Sprintf("tcp:%v,tcp:%v", listenAddr, dialAddr)
	stream, err = proxy.ParseStream(s)
	if err != nil {
		return proxy.Stream{}, false, fmt.Errorf("parse stream: %w", err)
	}

	return stream, isLoopback(host), nil
}

// getTargetAddr returns the network address pointed by a given
// target.
//
// If the target is a [types.IP] or a [types.Hostname], its identifier
// is returned straightaway.
//
// If the target is a [types.WebAddress], the identifier is parsed as
// URL. If it is a valid URL, the corresponding host[:port] is
// returned. Otherwise, the function returns error.
//
// If the target is a [types.GitRepository], the identifier is parsed
// as a Git URL. If it is a valid Git URL, the corresponding
// host[:port] is returned. Otherwise, the function returns error.
//
// [git-fetch documentation] points out that remote Git URLs may use
// any of the following syntaxes:
//
//   - ssh://[user@]host.xz[:port]/~[user]/path/to/repo.git/
//   - git://host.xz[:port]/~[user]/path/to/repo.git/
//   - http[s]://host.xz[:port]/path/to/repo.git/
//   - ftp[s]://host.xz[:port]/path/to/repo.git/
//   - [user@]host.xz:/~[user]/path/to/repo.git/
//
// For any other asset type, the function returns an error.
//
// [git-fetch documentation]: https://git-scm.com/docs/git-fetch#URLS
func getTargetAddr(target config.Target) (string, error) {
	switch target.AssetType {
	case types.IP, types.Hostname:
		return target.Identifier, nil
	case types.WebAddress:
		u, err := url.Parse(target.Identifier)
		if err != nil {
			return "", fmt.Errorf("parse URL: %w", err)
		}
		if u.Host == "" {
			return "", fmt.Errorf("empty URL host: %v", u)
		}
		return guessHostPort(u), nil
	case types.GitRepository:
		u, err := parseGitURL(target.Identifier)
		if err != nil {
			return "", fmt.Errorf("parse Git URL: %w", err)
		}
		if u.Host == "" {
			return "", fmt.Errorf("empty Git URL host: %v", u)
		}
		return guessHostPort(u), nil
	}
	return "", fmt.Errorf("invalid asset type: %v", target.AssetType)
}

// guessHostPort tries to guess the port corresponding to the provided
// URL and returns host:port. If the URL specifies a port, it is used.
// Otherwise, if the URL specifies a scheme, the default port for that
// scheme is used. Finally, if it is not possible to guess a port,
// only the host is returned.
func guessHostPort(u *url.URL) string {
	if u.Port() != "" {
		return u.Host
	}

	host := u.Hostname()
	if port, err := net.LookupPort("tcp", u.Scheme); err == nil {
		return net.JoinHostPort(host, strconv.Itoa(port))
	}
	return host
}

// mkIntIdentifier returns the identifier of the provided target after
// replacing the host with the Docker internal host. If it is not
// possible to generate an internal target from the provided asset
// type the function returns an error.
func mkIntIdentifier(target config.Target) (string, error) {
	switch target.AssetType {
	case types.IP, types.Hostname:
		return dockerInternalHost, nil
	case types.WebAddress:
		u, err := url.Parse(target.Identifier)
		if err != nil {
			return "", fmt.Errorf("parse URL: %w", err)
		}
		return mkIntURL(u), nil
	case types.GitRepository:
		u, err := parseGitURL(target.Identifier)
		if err != nil {
			return "", fmt.Errorf("parse Git URL: %w", err)
		}
		return mkIntURL(u), nil
	}
	return "", fmt.Errorf("invalid asset type: %v", target.AssetType)
}

// mkIntURL returns the string representation of the provided URL
// after replacing its host with the Docker internal host.
func mkIntURL(u *url.URL) string {
	host := dockerInternalHost
	if port := u.Port(); port != "" {
		host = net.JoinHostPort(host, port)
	}
	u.Host = host
	return u.String()
}

// isLoopback returns whether host is a loopback address.
func isLoopback(host string) bool {
	ips, err := net.LookupIP(host)
	if err != nil {
		return false
	}

	for _, ip := range ips {
		if ip.IsLoopback() {
			return true
		}
	}
	return false
}

// parseGitURL parses a Git URL. If gitURL is a scp-like Git URL, it
// is first converted into a SSH URL.
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
