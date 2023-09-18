// Copyright 2023 Adevinta

// Package engine runs Vulcan checks and retrieves the generated
// reports.
package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"path"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/adevinta/vulcan-agent/agent"
	"github.com/adevinta/vulcan-agent/backend"
	"github.com/adevinta/vulcan-agent/backend/docker"
	agentconfig "github.com/adevinta/vulcan-agent/config"
	"github.com/adevinta/vulcan-agent/jobrunner"
	"github.com/adevinta/vulcan-agent/queue"
	"github.com/adevinta/vulcan-agent/queue/chanqueue"
	report "github.com/adevinta/vulcan-report"
	types "github.com/adevinta/vulcan-types"
	"github.com/jroimartin/proxy"

	"github.com/adevinta/lava/config"
	"github.com/adevinta/lava/dockerutil"
)

// dockerInternalHost is the host used by the containers to access the
// services exposed by the Docker host.
const dockerInternalHost = "host.docker.internal"

// Report is a collection of reports returned by Vulcan checks and
// indexed by check ID.
type Report map[string]report.Report

// Run runs vulcan checks and returns the generated report. The check
// list is based on the provided checktypes and targets. These checks
// are run by a Vulcan agent, which is configured using the specified
// configuration.
func Run(checktypesURLs []string, targets []config.Target, cfg config.AgentConfig) (Report, error) {
	checktypes, err := config.NewChecktypeCatalog(checktypesURLs)
	if err != nil {
		return nil, fmt.Errorf("get checkype catalog: %w", err)
	}

	jl, err := newJobList(checktypes, targets)
	if err != nil {
		return nil, fmt.Errorf("create job list: %w", err)
	}

	if len(jl) == 0 {
		return nil, nil
	}

	agentConfig, err := newAgentConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("get agent config: %w", err)
	}

	alogger := newAgentLogger(slog.Default())

	backend, err := docker.NewBackend(alogger, agentConfig, beforeRun)
	if err != nil {
		return nil, fmt.Errorf("new Docker backend: %w", err)
	}

	jobsQueue := chanqueue.New(nil)
	if err := sendJobs(jl, jobsQueue); err != nil {
		return nil, fmt.Errorf("send jobs: %w", err)
	}

	// Create a state queue and discard all messages.
	stateQueue := chanqueue.New(queue.Discard())
	stateQueue.StartReading(context.Background())

	reports := &reportStore{}

	pg, err := proxyLocalTargets(targets)
	if err != nil {
		return nil, fmt.Errorf("proxy local services: %w", err)
	}
	defer pg.Close()

	exitCode := agent.RunWithQueues(agentConfig, reports, backend, stateQueue, jobsQueue, alogger)
	if exitCode != 0 {
		return nil, fmt.Errorf("run agent: exit code %v", exitCode)
	}

	// TODO(rm): show progress every few seconds during the scan
	// to prevent CI/CD issues due to inactivity.
	return reports.reports, nil
}

// beforeRun is called by the agent before creating each check
// container.
//
// TODO(rm): handle Git repositories.
func beforeRun(params backend.RunParams, rc *docker.RunConfig) error {
	// Register a host pointing to the host gateway.
	rc.HostConfig.ExtraHosts = []string{dockerInternalHost + ":host-gateway"}

	// Allow all checks to scan local assets.
	rc.ContainerConfig.Env = setenv(rc.ContainerConfig.Env, "VULCAN_ALLOW_PRIVATE_IPS", "true")
	rc.ContainerConfig.Env = setenv(rc.ContainerConfig.Env, "VULCAN_SKIP_REACHABILITY", "true")

	// Remote Docker daemons are not supported because, among
	// other things, it would require passing credentials to the
	// checks.
	dockerHost, err := daemonHost()
	if err != nil {
		return fmt.Errorf("get Docker client: %w", err)
	}
	if strings.HasPrefix(dockerHost, "unix://") {
		rc.ContainerConfig.Env = setenv(rc.ContainerConfig.Env, "DOCKER_HOST", dockerHost)
		dockerVol := strings.TrimPrefix(dockerHost, "unix://")
		rc.HostConfig.Binds = append(rc.HostConfig.Binds, dockerVol+":"+dockerVol)
	}

	// Modify the target sent to the check to point to the right
	// host.
	target, err := fixCheckTarget(params.Target, params.AssetType)
	if err != nil {
		return fmt.Errorf("fix check target: %w", err)
	}
	rc.ContainerConfig.Env = setenv(rc.ContainerConfig.Env, backend.CheckTargetVar, target)

	return nil
}

// fixCheckTarget extracts the host from the provided target and
// replaces it with the Docker internal host if it is bound to a
// loopback device. Otherwise, target is returned unchanged.
func fixCheckTarget(target, assetType string) (string, error) {
	switch types.AssetType(assetType) {
	case types.IP, types.Hostname:
		if isLoopback(target) {
			target = dockerInternalHost
		}
	case types.WebAddress:
		u, err := url.Parse(target)
		if err != nil {
			return "", fmt.Errorf("parse URL: %w", err)
		}
		fixURL(u)
		target = u.String()
	case types.GitRepository:
		u, err := parseGitURL(target)
		if err != nil {
			return "", fmt.Errorf("parse Git URL: %w", err)
		}
		fixURL(u)
		target = u.String()
	}
	return target, nil
}

// fixURL replaces the host of the provided URL with the Docker
// internal host if the URL host is bound to a loopback device.
// Otherwise, u is not changed.
func fixURL(u *url.URL) {
	if !isLoopback(u.Hostname()) {
		return
	}

	host := dockerInternalHost
	if port := u.Port(); port != "" {
		host = net.JoinHostPort(host, port)
	}
	u.Host = host
}

// setenv sets the value of the variable named by the key in the
// provided environment. An environment consists on a slice of strings
// with the format "key=value".
func setenv(env []string, key, value string) []string {
	for i, ev := range env {
		if strings.HasPrefix(ev, key+"=") {
			env[i] = fmt.Sprintf("%s=%s", key, value)
			return env
		}
	}
	return append(env, fmt.Sprintf("%s=%s", key, value))
}

// newAgentConfig creates a new [agentconfig.Config] based on the
// provided Lava configuration.
func newAgentConfig(cfg config.AgentConfig) (agentconfig.Config, error) {
	listenHost, err := bridgeHost()
	if err != nil {
		return agentconfig.Config{}, fmt.Errorf("get listen host: %w", err)
	}

	parallel := cfg.Parallel
	if parallel == 0 {
		parallel = 1
	}

	ln, err := net.Listen("tcp", listenHost+":0")
	if err != nil {
		return agentconfig.Config{}, fmt.Errorf("listen: %w", err)
	}

	auths := []agentconfig.Auth{}
	for _, r := range cfg.RegistriesAuth {
		auths = append(auths, agentconfig.Auth{
			Server: r.Server,
			User:   r.Username,
			Pass:   r.Password,
		})
	}

	acfg := agentconfig.Config{
		Agent: agentconfig.AgentConfig{
			ConcurrentJobs:         parallel,
			MaxNoMsgsInterval:      5,   // Low as all the messages will be in the queue before starting the agent.
			MaxProcessMessageTimes: 1,   // No retry.
			Timeout:                180, // Default timeout of 3 minutes.
		},
		API: agentconfig.APIConfig{
			Host:     dockerInternalHost,
			Listener: ln,
		},
		Check: agentconfig.CheckConfig{
			Vars: cfg.Vars,
		},
		Runtime: agentconfig.RuntimeConfig{
			Docker: agentconfig.DockerConfig{
				Registry: agentconfig.RegistryConfig{
					PullPolicy:          cfg.PullPolicy,
					BackoffMaxRetries:   5,
					BackoffInterval:     5,
					BackoffJitterFactor: 0.5,
					Auths:               auths,
				},
			},
		},
	}
	return acfg, nil
}

// sendJobs feeds the provided queue with jobs.
func sendJobs(jobs []jobrunner.Job, qw queue.Writer) error {
	for _, job := range jobs {
		job.StartTime = time.Now()
		bytes, err := json.Marshal(job)
		if err != nil {
			return fmt.Errorf("marshal json: %w", err)
		}
		if err := qw.Write(string(bytes)); err != nil {
			return fmt.Errorf("queue write: %w", err)
		}
	}
	return nil
}

// proxyLocalTargets detects targets listening on a loopback device
// and exposes them to the default bridge Docker network using the
// returned [proxy.Group]. The caller must close the returned proxy
// group.
func proxyLocalTargets(targets []config.Target) (*proxy.Group, error) {
	streams, err := proxyStreams(targets)
	if err != nil {
		return nil, fmt.Errorf("local streams: %w", err)
	}

	pg := &proxy.Group{}

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
			// proxies, but there might be other proxies
			// listening. So, close all of them.
			pg.Close()
			return nil, fmt.Errorf("proxy group: %w", err)
		case <-done:
			// All proxies are listening.
			break loop
		}
	}
	return pg, nil
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
			return nil, fmt.Errorf("split host port: %w", err)
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
// URL. If it is a valid URL, the corresponding host is returned.
// Otherwise, the function returns error.
//
// If the target is a [types.GitRepository], the identifier is parsed
// as a Git URL. If it is a valid Git URL, the corresponding host is
// returned. Otherwise, the function returns error.
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
		return u.Host, nil
	case types.GitRepository:
		u, err := parseGitURL(target.Identifier)
		if err != nil {
			return "", fmt.Errorf("parse Git URL: %w", err)
		}
		if u.Host == "" {
			return "", fmt.Errorf("empty Git URL host: %v", u)
		}
		return u.Host, nil
	}

	return "", errors.New("invalid asset type")
}

// isLoopback returns true if host resolves to an IP assigned to a
// loopback device.
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

// daemonHost returns the Docker daemon host.
func daemonHost() (string, error) {
	cli, err := dockerutil.NewAPIClient()
	if err != nil {
		return "", fmt.Errorf("get Docker client: %w", err)
	}
	defer cli.Close()

	return cli.DaemonHost(), nil
}

// bridgeHost returns a host that points to the Docker host and is
// reachable from the containers running in the default bridge.
func bridgeHost() (string, error) {
	cli, err := dockerutil.NewAPIClient()
	if err != nil {
		return "", fmt.Errorf("get Docker client: %w", err)
	}
	defer cli.Close()

	host, err := dockerutil.BridgeHost(cli)
	if err != nil {
		return "", fmt.Errorf("get bridge host: %w", err)
	}

	return host, nil
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
