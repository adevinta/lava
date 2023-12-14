// Copyright 2023 Adevinta

// Package engine runs Vulcan checks and retrieves the generated
// reports.
package engine

import (
	"context"
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
	types "github.com/adevinta/vulcan-types"

	"github.com/adevinta/lava/internal/checktypes"
	"github.com/adevinta/lava/internal/config"
	"github.com/adevinta/lava/internal/dockerutil"
	"github.com/adevinta/lava/internal/metrics"
)

// dockerInternalHost is the host used by the containers to access the
// services exposed by the Docker host.
const dockerInternalHost = "host.lava.internal"

// Report is a collection of reports returned by Vulcan checks and
// indexed by check ID.
type Report map[string]report.Report

// Run runs vulcan checks and returns the generated report. The check
// list is based on the provided checktypes and targets. These checks
// are run by a Vulcan agent, which is configured using the specified
// configuration.
func Run(checktypeURLs []string, targets []config.Target, cfg config.AgentConfig) (Report, error) {
	srv, err := newTargetServer()
	if err != nil {
		return nil, fmt.Errorf("new server: %w", err)
	}
	defer srv.Close()

	catalog, err := checktypes.NewCatalog(checktypeURLs)
	if err != nil {
		return nil, fmt.Errorf("get checkype catalog: %w", err)
	}

	metrics.Collect("checktypes", catalog)

	jl, err := generateJobs(catalog, targets)
	if err != nil {
		return nil, fmt.Errorf("create job list: %w", err)
	}

	if len(jl) == 0 {
		return nil, nil
	}

	return runAgent(jl, srv, cfg)
}

// summaryInterval is the time between summary logs.
const summaryInterval = 15 * time.Second

// runAgent creates a Vulcan agent using the specified config and uses
// it to run the provided jobs.
func runAgent(jobs []jobrunner.Job, srv *targetServer, cfg config.AgentConfig) (Report, error) {
	alogger := newAgentLogger(slog.Default())

	agentConfig, err := newAgentConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("get agent config: %w", err)
	}

	br := func(params backend.RunParams, rc *docker.RunConfig) error {
		return beforeRun(params, rc, srv)
	}

	backend, err := docker.NewBackend(alogger, agentConfig, br)
	if err != nil {
		return nil, fmt.Errorf("new Docker backend: %w", err)
	}

	// Create a state queue and discard all messages.
	stateQueue := chanqueue.New(queue.Discard())
	stateQueue.StartReading(context.Background())

	jobsQueue := chanqueue.New(nil)
	if err := sendJobs(jobs, jobsQueue); err != nil {
		return nil, fmt.Errorf("send jobs: %w", err)
	}

	rs := &reportStore{}

	done := make(chan bool)
	go func() {
		for {
			select {
			case <-done:
				return
			case <-time.After(summaryInterval):
				sums := rs.Summary()
				if len(sums) == 0 {
					slog.Info("waiting for updates")
					break
				}
				for _, s := range sums {
					slog.Info(s)
				}
			}
		}
	}()

	exitCode := agent.RunWithQueues(agentConfig, rs, backend, stateQueue, jobsQueue, alogger)
	if exitCode != 0 {
		return nil, fmt.Errorf("run agent: exit code %v", exitCode)
	}

	done <- true

	report, err := mkReport(rs, srv)
	if err != nil {
		return nil, fmt.Errorf("restore targets: %w", err)
	}

	return report, nil
}

// mkReport generates a report from the information stored in the
// provided [reportStore]. It uses the provided [targetServer] to
// replace the targets sent to the checks with the original targets.
func mkReport(rs *reportStore, srv *targetServer) (Report, error) {
	rep := make(Report)
	for checkID, r := range rs.Reports() {
		tm, ok := srv.TargetMap(checkID)
		if !ok {
			rep[checkID] = r
			continue
		}

		tmAddrs := tm.Addrs()

		slog.Info("applying target map", "check", checkID, "tm", tm, "tmAddr", tmAddrs)

		r.Target = tm.OldIdentifier

		var vulns []report.Vulnerability
		for _, vuln := range r.Vulnerabilities {
			vuln = vulnReplaceAll(vuln, tm.NewIdentifier, tm.OldIdentifier)
			vuln = vulnReplaceAll(vuln, tmAddrs.NewIdentifier, tmAddrs.OldIdentifier)
			vulns = append(vulns, vuln)
		}
		r.Vulnerabilities = vulns

		rep[checkID] = r
	}
	return rep, nil
}

// vulnReplaceAll returns a copy of the vulnerability vuln with all
// non-overlapping instances of old replaced by new.
func vulnReplaceAll(vuln report.Vulnerability, old, new string) report.Vulnerability {
	vuln.Summary = strings.ReplaceAll(vuln.Summary, old, new)
	vuln.AffectedResource = strings.ReplaceAll(vuln.AffectedResource, old, new)
	vuln.AffectedResourceString = strings.ReplaceAll(vuln.AffectedResourceString, old, new)
	vuln.Description = strings.ReplaceAll(vuln.Description, old, new)
	vuln.Details = strings.ReplaceAll(vuln.Details, old, new)
	vuln.ImpactDetails = strings.ReplaceAll(vuln.ImpactDetails, old, new)

	var labels []string
	for _, label := range vuln.Labels {
		labels = append(labels, strings.ReplaceAll(label, old, new))
	}
	vuln.Labels = labels

	var recs []string
	for _, rec := range vuln.Recommendations {
		recs = append(recs, strings.ReplaceAll(rec, old, new))
	}
	vuln.Recommendations = recs

	var refs []string
	for _, ref := range vuln.References {
		refs = append(refs, strings.ReplaceAll(ref, old, new))
	}
	vuln.References = refs

	var rscs []report.ResourcesGroup
	for _, rsc := range vuln.Resources {
		rscs = append(rscs, rscReplaceAll(rsc, old, new))
	}
	vuln.Resources = rscs

	var vulns []report.Vulnerability
	for _, vuln := range vuln.Vulnerabilities {
		vulns = append(vulns, vulnReplaceAll(vuln, old, new))
	}
	vuln.Vulnerabilities = vulns

	return vuln
}

// rscReplaceAll returns a copy of the resource group rsc with all
// non-overlapping instances of old replaced by new.
func rscReplaceAll(rsc report.ResourcesGroup, old, new string) report.ResourcesGroup {
	rsc.Name = strings.ReplaceAll(rsc.Name, old, new)

	var hdrs []string
	for _, hdr := range rsc.Header {
		hdrs = append(hdrs, strings.ReplaceAll(hdr, old, new))
	}
	rsc.Header = hdrs

	var rows []map[string]string
	for _, r := range rsc.Rows {
		row := make(map[string]string)
		for k, v := range r {
			k = strings.ReplaceAll(k, old, new)
			v = strings.ReplaceAll(v, old, new)
			row[k] = v
		}
		rows = append(rows, row)
	}
	rsc.Rows = rows

	return rsc
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

	ln, err := net.Listen("tcp", net.JoinHostPort(listenHost, "0"))
	if err != nil {
		return agentconfig.Config{}, fmt.Errorf("listen: %w", err)
	}

	auths := []agentconfig.Auth{}
	for _, r := range cfg.RegistryAuths {
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
func beforeRun(params backend.RunParams, rc *docker.RunConfig, srv *targetServer) error {
	// Register a host pointing to the host gateway.
	rc.HostConfig.ExtraHosts = []string{dockerInternalHost + ":host-gateway"}

	// Allow all checks to scan local assets.
	rc.ContainerConfig.Env = setenv(rc.ContainerConfig.Env, "VULCAN_ALLOW_PRIVATE_IPS", "true")

	if params.AssetType == string(types.DockerImage) {
		// Due to how reachability is defined by the Vulcan
		// check SDK, local Docker images would be identified
		// as unreachable. So, we disable reachability checks
		// for this type of assets.
		rc.ContainerConfig.Env = setenv(rc.ContainerConfig.Env, "VULCAN_SKIP_REACHABILITY", "true")

		// Tools like trivy require access to the Docker
		// daemon to scan local Docker images. So, we share
		// the Docker socket with them.
		dockerHost, err := daemonHost()
		if err != nil {
			return fmt.Errorf("get Docker client: %w", err)
		}

		// Remote Docker daemons are not supported.
		if dockerVol, found := strings.CutPrefix(dockerHost, "unix://"); found {
			rc.HostConfig.Binds = append(rc.HostConfig.Binds, dockerVol+":/var/run/docker.sock")
		}
	}

	// Proxy local targets and serve Git repositories.
	target := config.Target{
		Identifier: params.Target,
		AssetType:  types.AssetType(params.AssetType),
	}
	if tm, err := srv.Handle(params.CheckID, target); err == nil {
		if !tm.IsZero() {
			rc.ContainerConfig.Env = setenv(rc.ContainerConfig.Env, "VULCAN_CHECK_TARGET", tm.NewIdentifier)
			rc.ContainerConfig.Env = setenv(rc.ContainerConfig.Env, "VULCAN_CHECK_ASSET_TYPE", string(tm.NewAssetType))
		}
	} else {
		slog.Warn("could not handle target", "target", target, "err", err)
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
