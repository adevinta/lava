// Copyright 2023 Adevinta

package engine

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strconv"
	"sync"
	"syscall"

	types "github.com/adevinta/vulcan-types"
	"github.com/jroimartin/proxy"

	"github.com/adevinta/lava/config"
)

// updateAndProxyLocalTargets detects targets listening on a loopback
// device and exposes them to the default bridge Docker network using
// the provided [proxy.Group]. These targets are updated with the
// address of the corresponding proxy.
func updateAndProxyLocalTargets(pg *proxy.Group, targets []config.Target) error {
	streams, err := proxyStreams(targets)
	if err != nil {
		return fmt.Errorf("local streams: %w", err)
	}

	for i := range targets {
		if err := updateLocalTarget(&targets[i]); err != nil {
			return fmt.Errorf("update local target: %w", err)
		}
	}

	var wg sync.WaitGroup
	pg.BeforeAccept = func() error {
		wg.Done()
		return nil
	}
	wg.Add(len(streams))

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	errc := pg.ListenAndServe(streams)

loop:
	for {
		select {
		case err := <-errc:
			// No listeners.
			if errors.Is(err, proxy.ErrGroupClosed) {
				break loop
			}

			// If there is a service already listening on
			// that address, then assume that it is the
			// target service and ignore the error.
			if errors.Is(err, syscall.EADDRINUSE) {
				continue
			}

			// An unexpected error happened in one of the
			// proxies.
			return fmt.Errorf("proxy group: %w", err)
		case <-done:
			// All proxies are listening.
			break loop
		}
	}
	return nil
}

// proxyStreams generates a list of [proxy.Stream] for the targets
// listening on a loopback device.
func proxyStreams(targets []config.Target) ([]proxy.Stream, error) {
	addrs := make(map[string]struct{})
	for _, t := range targets {
		addr, err := targetAddr(t)
		if err != nil {
			continue
		}
		addrs[addr] = struct{}{}
	}

	listenHost, err := bridgeHost()
	if err != nil {
		return nil, fmt.Errorf("get listen host: %w", err)
	}

	var streams []proxy.Stream
	for addr := range addrs {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			slog.Warn("could not split host port", "err", err)
			continue
		}
		if !isLoopback(host) {
			continue
		}

		listenAddr := net.JoinHostPort(listenHost, port)
		dialAddr := net.JoinHostPort(host, port)
		s := fmt.Sprintf("tcp:%v,tcp:%v", listenAddr, dialAddr)
		stream, err := proxy.ParseStream(s)
		if err != nil {
			return nil, fmt.Errorf("parse stream: %w", err)
		}

		streams = append(streams, stream)
	}
	return streams, nil
}

// targetAddr returns the network address pointed by a given target.
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
// For any other asset type, the function returns an invalid asset
// type error.
//
// [git-fetch documentation]: https://git-scm.com/docs/git-fetch#URLS
func targetAddr(target config.Target) (string, error) {
	switch types.AssetType(target.AssetType) {
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

	return "", errors.New("invalid asset type")
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

// updateLocalTarget extracts the host from the provided target and
// replaces it in-place with the Docker internal host if it is bound
// to a loopback device. Otherwise, target is not changed.
func updateLocalTarget(target *config.Target) error {
	switch types.AssetType(target.AssetType) {
	case types.IP, types.Hostname:
		if isLoopback(target.Identifier) {
			target.Identifier = dockerInternalHost
		}
	case types.WebAddress:
		u, err := url.Parse(target.Identifier)
		if err != nil {
			return fmt.Errorf("parse URL: %w", err)
		}
		updateLocalURL(u)
		target.Identifier = u.String()
	case types.GitRepository:
		u, err := parseGitURL(target.Identifier)
		if err != nil {
			return fmt.Errorf("parse Git URL: %w", err)
		}
		updateLocalURL(u)
		target.Identifier = u.String()
	}
	return nil
}

// updateLocalURL replaces the host of the provided URL with the
// Docker internal host if the URL host is bound to a loopback device.
// Otherwise, u is not changed.
func updateLocalURL(u *url.URL) {
	if !isLoopback(u.Hostname()) {
		return
	}

	host := dockerInternalHost
	if port := u.Port(); port != "" {
		host = net.JoinHostPort(host, port)
	}
	u.Host = host
}
