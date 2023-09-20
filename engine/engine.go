// Copyright 2023 Adevinta

// Package engine runs Vulcan checks and retrieves the generated
// reports.
package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/adevinta/vulcan-agent/agent"
	"github.com/adevinta/vulcan-agent/backend"
	"github.com/adevinta/vulcan-agent/backend/docker"
	agentconfig "github.com/adevinta/vulcan-agent/config"
	"github.com/adevinta/vulcan-agent/jobrunner"
	"github.com/adevinta/vulcan-agent/queue"
	"github.com/adevinta/vulcan-agent/queue/chanqueue"
	report "github.com/adevinta/vulcan-report"
	"github.com/jroimartin/proxy"

	"github.com/adevinta/lava/config"
	"github.com/adevinta/lava/dockerutil"
	"github.com/adevinta/lava/gitserver"
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
	gs, err := gitserver.New()
	if err != nil {
		return nil, fmt.Errorf("new GitServer: %w", err)
	}
	defer gs.Close()

	// updateAndServeLocalGitRepos must be called before calling
	// updateAndProxyLocalTargets.
	//
	// updateAndServeLocalGitRepos updates the targets
	// corresponding to local Git repositories (local directories)
	// with the address of the Git server. This Git server listens
	// on a loopback device that must be proxied later by
	// updateAndProxyLocalTargets.
	if err := updateAndServeLocalGitRepos(gs, targets); err != nil {
		return nil, fmt.Errorf("serve local Git repositories: %w", err)
	}

	pg := &proxy.Group{}
	defer pg.Close()

	if err := updateAndProxyLocalTargets(pg, targets); err != nil {
		return nil, fmt.Errorf("proxy local services: %w", err)
	}

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

	return runAgent(jl, cfg)
}

// summaryInterval is the time between summary logs.
const summaryInterval = 15 * time.Second

// runAgent creates a Vulcan agent using the specified config and uses
// it to run the provided jobs.
func runAgent(jl jobList, cfg config.AgentConfig) (Report, error) {
	alogger := newAgentLogger(slog.Default())

	agentConfig, err := newAgentConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("get agent config: %w", err)
	}

	backend, err := docker.NewBackend(alogger, agentConfig, beforeRun)
	if err != nil {
		return nil, fmt.Errorf("new Docker backend: %w", err)
	}

	// Create a state queue and discard all messages.
	stateQueue := chanqueue.New(queue.Discard())
	stateQueue.StartReading(context.Background())

	jobsQueue := chanqueue.New(nil)
	if err := sendJobs(jl, jobsQueue); err != nil {
		return nil, fmt.Errorf("send jobs: %w", err)
	}

	reports := &reportStore{}

	done := make(chan bool)
	go func() {
		for {
			select {
			case <-done:
				return
			case <-time.After(summaryInterval):
				slog.Info("status update", "summary", reports.Summary())
			}
		}
	}()

	exitCode := agent.RunWithQueues(agentConfig, reports, backend, stateQueue, jobsQueue, alogger)
	if exitCode != 0 {
		return nil, fmt.Errorf("run agent: exit code %v", exitCode)
	}

	done <- true

	return reports.reports, nil
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

// beforeRun is called by the agent before creating each check
// container.
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

	return nil
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
