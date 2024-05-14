// Copyright 2023 Adevinta

// Package containers allows to interact with different container
// engines.
package containers

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"

	"github.com/docker/cli/cli/command"
	"github.com/docker/cli/cli/config"
	"github.com/docker/cli/cli/flags"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/archive"
	"github.com/docker/go-connections/tlsconfig"
)

// ErrInvalidRuntime means that the provided container runtime is not
// supported.
var ErrInvalidRuntime = errors.New("invalid runtime")

// Runtime is the container runtime.
type Runtime int

// Container runtimes.
const (
	RuntimeDockerd               Runtime = iota // Docker Engine
	RuntimeDockerdDockerDesktop                 // Docker Desktop
	RuntimeDockerdRancherDesktop                // Rancher Desktop (dockerd)
	RuntimeDockerdPodmanDesktop                 // Podman Desktop (dockerd)
)

var runtimeNames = map[string]Runtime{
	"Dockerd":               RuntimeDockerd,
	"DockerdDockerDesktop":  RuntimeDockerdDockerDesktop,
	"DockerdRancherDesktop": RuntimeDockerdRancherDesktop,
	"DockerdPodmanDesktop":  RuntimeDockerdPodmanDesktop,
}

// ParseRuntime converts a runtime name into a [Runtime] value. It
// returns error if the provided name does not match any known
// container runtime.
func ParseRuntime(s string) (Runtime, error) {
	if rt, ok := runtimeNames[s]; ok {
		return rt, nil
	}
	return Runtime(0), fmt.Errorf("%w: %v", ErrInvalidRuntime, s)
}

// GetenvRuntime gets the container runtime from the LAVA_RUNTIME
// environment variable.
func GetenvRuntime() (Runtime, error) {
	envRuntime := os.Getenv("LAVA_RUNTIME")
	if envRuntime == "" {
		return RuntimeDockerd, nil
	}

	rt, err := ParseRuntime(envRuntime)
	if err != nil {
		return Runtime(0), fmt.Errorf("parse runtime: %w", err)
	}
	return rt, nil
}

// UnmarshalText decodes a runtime name into a [Runtime] value. It
// returns error if the provided name does not match any known
// container runtime.
func (rt *Runtime) UnmarshalText(text []byte) error {
	runtime, err := ParseRuntime(string(text))
	if err != nil {
		return err
	}
	*rt = runtime
	return nil
}

// DockerdClient represents a Docker API client.
type DockerdClient struct {
	client.APIClient
	rt Runtime
}

// NewDockerdClient returns a new container runtime client compatible
// with the Docker API. Depending on the runtime being used (see
// [Runtime]), there can be small differences. The provided runtime
// allows to fine-tune the behavior of the client. This client behaves
// as close as possible to the Docker CLI. It gets its configuration
// from the Docker config file and honors the [Docker CLI environment
// variables]. It also sets up TLS authentication if TLS is enabled.
//
// [Docker CLI environment variables]: https://docs.docker.com/engine/reference/commandline/cli/#environment-variables
func NewDockerdClient(rt Runtime) (DockerdClient, error) {
	tlsVerify := os.Getenv(client.EnvTLSVerify) != ""

	var tlsopts *tlsconfig.Options
	if tlsVerify {
		certPath := os.Getenv(client.EnvOverrideCertPath)
		if certPath == "" {
			certPath = config.Dir()
		}
		tlsopts = &tlsconfig.Options{
			CAFile:   filepath.Join(certPath, flags.DefaultCaFile),
			CertFile: filepath.Join(certPath, flags.DefaultCertFile),
			KeyFile:  filepath.Join(certPath, flags.DefaultKeyFile),
		}
	}

	opts := &flags.ClientOptions{
		TLS:        tlsVerify,
		TLSVerify:  tlsVerify,
		TLSOptions: tlsopts,
	}

	acpicli, err := command.NewAPIClientFromFlags(opts, config.LoadDefaultConfigFile(io.Discard))
	if err != nil {
		return DockerdClient{}, fmt.Errorf("new Docker API Client: %w", err)
	}

	cli := DockerdClient{
		APIClient: acpicli,
		rt:        rt,
	}
	return cli, nil
}

// Close closes the transport used by the client.
func (cli *DockerdClient) Close() error {
	return cli.APIClient.Close()
}

// DaemonHost returns the host address used by the client.
func (cli *DockerdClient) DaemonHost() string {
	daemonHost := cli.APIClient.DaemonHost()

	u, err := url.Parse(daemonHost)
	if err != nil {
		slog.Warn("Docker daemon host is not a valid URL", "daemonHost", daemonHost)
		return daemonHost
	}

	// Docker Desktop cannot share Unix sockets unless it is the
	// Docker Unix socket and its path is exactly
	// "/var/run/docker.sock".
	if cli.rt == RuntimeDockerdDockerDesktop && u.Scheme == "unix" && path.Base(u.Path) == "docker.sock" {
		return "unix:///var/run/docker.sock"
	}

	return daemonHost
}

// HostGatewayHostname returns a hostname that points to the container
// engine host and is reachable from the containers.
func (cli *DockerdClient) HostGatewayHostname() string {
	if cli.rt == RuntimeDockerdPodmanDesktop {
		return "host.containers.internal"
	}
	return "host.docker.internal"
}

// HostGatewayMapping returns the host-to-IP mapping required by the
// containers to reach the container engine host. It returns an empty
// string if this mapping is not required.
func (cli *DockerdClient) HostGatewayMapping() string {
	if cli.rt == RuntimeDockerd {
		return cli.HostGatewayHostname() + ":host-gateway"
	}
	return ""
}

// HostGatewayInterfaceAddr returns the address of a local interface
// that is reachable from the containers.
func (cli *DockerdClient) HostGatewayInterfaceAddr() (string, error) {
	if cli.rt == RuntimeDockerd {
		gw, err := cli.bridgeGateway()
		if err != nil {
			return "", fmt.Errorf("get bridge gateway: %w", err)
		}
		return gw.IP.String(), nil
	}
	return "127.0.0.1", nil
}

// defaultDockerBridgeNetwork is the name of the default bridge
// network in Docker.
const defaultDockerBridgeNetwork = "bridge"

// bridgeGateway returns the gateway of the default Docker bridge
// network.
func (cli *DockerdClient) bridgeGateway() (*net.IPNet, error) {
	gws, err := cli.gateways(context.Background(), defaultDockerBridgeNetwork)
	if err != nil {
		return nil, fmt.Errorf("could not get Docker network gateway: %w", err)
	}
	if len(gws) != 1 {
		return nil, fmt.Errorf("unexpected number of gateways: %v", len(gws))
	}
	return gws[0], nil
}

// gateways returns the gateways of the specified Docker network.
func (cli *DockerdClient) gateways(ctx context.Context, network string) ([]*net.IPNet, error) {
	resp, err := cli.NetworkInspect(ctx, network, types.NetworkInspectOptions{})
	if err != nil {
		return nil, fmt.Errorf("network inspect: %w", err)
	}

	var gws []*net.IPNet
	for _, cfg := range resp.IPAM.Config {
		_, subnet, err := net.ParseCIDR(cfg.Subnet)
		if err != nil {
			return nil, fmt.Errorf("invalid subnet: %v", cfg.Subnet)
		}

		ip := net.ParseIP(cfg.Gateway)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP: %v", cfg.Gateway)
		}

		if !subnet.Contains(ip) {
			return nil, fmt.Errorf("subnet mismatch: ip: %v, subnet: %v", ip, subnet)
		}

		subnet.IP = ip
		gws = append(gws, subnet)
	}
	return gws, nil
}

// ImageBuild builds a Docker image in the context of a path using the
// provided dockerfile and assigns it the specified reference. It
// returns the ID of the new image.
func (cli *DockerdClient) ImageBuild(ctx context.Context, path, dockerfile, ref string) (id string, err error) {
	tar, err := archive.TarWithOptions(path, &archive.TarOptions{})
	if err != nil {
		return "", fmt.Errorf("new tar: %w", err)
	}

	opts := types.ImageBuildOptions{
		Tags:       []string{ref},
		Dockerfile: dockerfile,
		Remove:     true,
	}
	resp, err := cli.APIClient.ImageBuild(ctx, tar, opts)
	if err != nil {
		return "", fmt.Errorf("image build: %w", err)
	}
	defer resp.Body.Close()

	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	summ, err := cli.ImageList(context.Background(), image.ListOptions{
		Filters: filters.NewArgs(filters.Arg("reference", ref)),
	})
	if err != nil {
		return "", fmt.Errorf("image list: %w", err)
	}

	if len(summ) != 1 {
		return "", fmt.Errorf("image list: unexpected number of images: %v", len(summ))
	}

	return summ[0].ID, nil
}
