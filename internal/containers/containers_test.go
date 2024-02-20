// Copyright 2023 Adevinta

package containers

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestParseRuntime(t *testing.T) {
	tests := []struct {
		name       string
		rtName     string
		want       Runtime
		wantNilErr bool
	}{
		{
			name:       "valid runtime",
			rtName:     "DockerdDockerDesktop",
			want:       RuntimeDockerdDockerDesktop,
			wantNilErr: true,
		},
		{
			name:       "invalid runtime",
			rtName:     "Invalid",
			want:       Runtime(0),
			wantNilErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRuntime(tt.rtName)

			if (err == nil) != tt.wantNilErr {
				t.Errorf("unexpected error: %v", err)
			}

			if got != tt.want {
				t.Errorf("unexpected runtime: got: %v, want: %v", tt.want, got)
			}
		})
	}
}

func TestGetenvRuntime(t *testing.T) {
	tests := []struct {
		name       string
		env        string
		want       Runtime
		wantNilErr bool
	}{
		{
			name:       "empty env var",
			env:        "",
			want:       RuntimeDockerd,
			wantNilErr: true,
		},
		{
			name:       "dockerd podman desktop",
			env:        "DockerdPodmanDesktop",
			want:       RuntimeDockerdPodmanDesktop,
			wantNilErr: true,
		},
		{
			name:       "invalid runtime",
			env:        "Invalid",
			want:       Runtime(0),
			wantNilErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("LAVA_RUNTIME", tt.env)

			got, err := GetenvRuntime()

			if (err == nil) != tt.wantNilErr {
				t.Errorf("unexpected error: %v", err)
			}

			if got != tt.want {
				t.Errorf("unexpected runtime: got: %v, want: %v", got, tt.want)
			}
		})
	}
}

func TestRuntime_UnmarshalText(t *testing.T) {
	type JSONData struct {
		Runtime Runtime `json:"runtime"`
	}

	tests := []struct {
		name       string
		data       string
		want       JSONData
		wantNilErr bool
	}{
		{
			name:       "valid runtime",
			data:       `{"runtime": "DockerdRancherDesktop"}`,
			want:       JSONData{Runtime: RuntimeDockerdRancherDesktop},
			wantNilErr: true,
		},
		{
			name:       "invalid runtime",
			data:       `{"runtime": "Invalid"}`,
			want:       JSONData{},
			wantNilErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got JSONData

			err := json.Unmarshal([]byte(tt.data), &got)

			if (err == nil) != tt.wantNilErr {
				t.Errorf("unexpected error: %v", err)
			}

			if got != tt.want {
				t.Errorf("unexpected runtime: got: %v, want: %v", tt.want, got)
			}
		})
	}
}

var (
	bridgeCfgs = []ipamConfig{{Subnet: "172.17.0.0/16", Gateway: "172.17.0.1"}}
	bridgeAddr = &net.IPNet{IP: net.ParseIP("172.17.0.1"), Mask: net.CIDRMask(16, 32)}

	defaultAPITestdata = apiTestdata{
		networks: map[string]networkTestdata{
			defaultDockerBridgeNetwork: {
				cfgs:          bridgeCfgs,
				gateways:      []*net.IPNet{bridgeAddr},
				bridgeGateway: bridgeAddr,
			},
			"multi": {
				cfgs: []ipamConfig{
					{Subnet: "172.18.0.0/16", Gateway: "172.18.0.1"},
					{Subnet: "172.19.0.0/16", Gateway: "172.19.0.10"},
				},
				gateways: []*net.IPNet{
					{IP: net.ParseIP("172.18.0.1"), Mask: net.CIDRMask(16, 32)},
					{IP: net.ParseIP("172.19.0.10"), Mask: net.CIDRMask(16, 32)},
				},
			},
			"empty": {},
			"mismatch": {
				cfgs: []ipamConfig{
					{Subnet: "172.17.0.0/16", Gateway: "172.18.0.1"},
				},
			},
			"badgateway": {
				cfgs: []ipamConfig{
					{Subnet: "172.18.0.0/16", Gateway: "172.18.0.555"},
				},
			},
			"badsubnet": {
				cfgs: []ipamConfig{
					{Subnet: "172.18.555.0/16", Gateway: "172.18.0.1"},
				},
			},
		},
		system: systemTestdata{
			id: "dockerutil",
		},
	}
)

func TestNewDockerdClient_tls(t *testing.T) {
	tests := []struct {
		name       string
		host       string
		wantID     string
		wantNilErr bool
	}{
		{
			name:       "success",
			host:       "127.0.0.1",
			wantID:     defaultAPITestdata.system.id,
			wantNilErr: true,
		},
		{
			name:       "error",
			host:       "localhost",
			wantID:     "",
			wantNilErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewUnstartedServer(testAPI{testdata: defaultAPITestdata})

			cert, err := tls.LoadX509KeyPair("testdata/certs/server-cert.pem", "testdata/certs/server-key.pem")
			if err != nil {
				panic(fmt.Sprintf("httptest: NewTLSServer: %v", err))
			}
			srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}

			srv.StartTLS()
			defer srv.Close()

			addr := srv.Listener.Addr().(*net.TCPAddr)
			dockerHost := fmt.Sprintf("tcp://%v:%v", tt.host, addr.Port)

			t.Setenv("DOCKER_CONFIG", "testdata")
			t.Setenv("DOCKER_CERT_PATH", "testdata/certs")
			t.Setenv("DOCKER_HOST", dockerHost)
			t.Setenv("DOCKER_TLS_VERIFY", "1")

			cli, err := NewDockerdClient(RuntimeDockerd)
			if err != nil {
				t.Fatalf("new API client: %v", err)
			}
			defer cli.Close()

			if dh := cli.DaemonHost(); dh != dockerHost {
				t.Errorf("unexpected daemon host: got: %v, want: %v", dh, dockerHost)
			}

			info, err := cli.Info(context.Background())

			if err == nil != tt.wantNilErr {
				t.Errorf("unexpected error: %v", err)
			}

			if err != nil {
				var tlsErr *tls.CertificateVerificationError
				if !errors.As(err, &tlsErr) {
					t.Errorf("error is not a TLS error: %v", err)
				}
			}

			if info.ID != tt.wantID {
				t.Errorf("unexpected system ID: got: %v, want: %v", info.ID, defaultAPITestdata.system.id)
			}
		})
	}
}

func TestDockerdClient_DaemonHost(t *testing.T) {
	const dockerHost = "tcp://example.com:1234"

	t.Setenv("DOCKER_CONFIG", "testdata/certs")
	t.Setenv("DOCKER_HOST", dockerHost)

	cli, err := NewDockerdClient(RuntimeDockerd)
	if err != nil {
		t.Fatalf("new API client: %v", err)
	}
	defer cli.Close()

	if dh := cli.DaemonHost(); dh != dockerHost {
		t.Errorf("unexpected daemon host: got: %v, want: %v", dh, dockerHost)
	}
}

func TestDockerdClient_HostGatewayHostname(t *testing.T) {
	tests := []struct {
		name string
		rt   Runtime
		want string
	}{
		{
			name: "dockerd",
			rt:   RuntimeDockerd,
			want: "host.docker.internal",
		},
		{
			name: "dockerd podman desktop",
			rt:   RuntimeDockerdPodmanDesktop,
			want: "host.containers.internal",
		},
		{
			name: "invalid runtime",
			rt:   Runtime(255),
			want: "host.docker.internal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cli, err := NewDockerdClient(tt.rt)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			defer cli.Close()

			got := cli.HostGatewayHostname()
			if got != tt.want {
				t.Errorf("unexpected hostname: got: %v, want: %v", got, tt.want)
			}
		})
	}
}

func TestDockerdClient_HostGatewayMapping(t *testing.T) {
	tests := []struct {
		name string
		rt   Runtime
		want string
	}{
		{
			name: "dockerd",
			rt:   RuntimeDockerd,
			want: "host.docker.internal:host-gateway",
		},
		{
			name: "dockerd podman desktop",
			rt:   RuntimeDockerdPodmanDesktop,
			want: "",
		},
		{
			name: "invalid runtime",
			rt:   Runtime(255),
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cli, err := NewDockerdClient(tt.rt)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			defer cli.Close()

			got := cli.HostGatewayMapping()
			if got != tt.want {
				t.Errorf("unexpected hostname: got: %v, want: %v", got, tt.want)
			}
		})
	}
}

func TestDockerdClient_gateways(t *testing.T) {
	tests := []struct {
		name       string
		net        string
		wantNilErr bool
	}{
		{
			name:       "default bridge network",
			net:        defaultDockerBridgeNetwork,
			wantNilErr: true,
		},
		{
			name:       "multiple gateways",
			net:        "multi",
			wantNilErr: true,
		},
		{
			name:       "no gateways",
			net:        "empty",
			wantNilErr: true,
		},
		{
			name:       "subnet mismatch",
			net:        "mismatch",
			wantNilErr: false,
		},
		{
			name:       "malformed subnet",
			net:        "badsubnet",
			wantNilErr: false,
		},
		{
			name:       "malformed gateway",
			net:        "badgateway",
			wantNilErr: false,
		},
		{
			name:       "api error",
			net:        "notfound",
			wantNilErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cli, err := newTestDockerdClient(t, RuntimeDockerd, defaultAPITestdata)
			if err != nil {
				t.Fatalf("new test client: %v", err)
			}
			defer cli.Close()

			got, err := cli.gateways(context.Background(), tt.net)

			if (err == nil) != tt.wantNilErr {
				t.Errorf("unexpected error: %v", err)
			}

			td := defaultAPITestdata.networks[tt.net]
			if diff := cmp.Diff(td.gateways, got); diff != "" {
				t.Errorf("gateways mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDockerdClient_bridgeGateway(t *testing.T) {
	tests := []struct {
		name       string
		td         apiTestdata
		wantNilErr bool
	}{
		{
			name:       "default bridge network",
			td:         defaultAPITestdata,
			wantNilErr: true,
		},
		{
			name: "multiple gateways",
			td: apiTestdata{
				networks: map[string]networkTestdata{
					defaultDockerBridgeNetwork: {
						cfgs: []ipamConfig{
							{Subnet: "172.18.0.0/16", Gateway: "172.18.0.1"},
							{Subnet: "172.19.0.0/16", Gateway: "172.19.0.10"},
						},
					},
				},
			},
			wantNilErr: false,
		},
		{
			name: "no gateways",
			td: apiTestdata{
				networks: map[string]networkTestdata{
					defaultDockerBridgeNetwork: {},
				},
			},
			wantNilErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cli, err := newTestDockerdClient(t, RuntimeDockerd, tt.td)
			if err != nil {
				t.Fatalf("new test client: %v", err)
			}
			defer cli.Close()

			got, err := cli.bridgeGateway()

			if (err == nil) != tt.wantNilErr {
				t.Errorf("unexpected error: %v", err)
			}

			want := tt.td.networks[defaultDockerBridgeNetwork].bridgeGateway
			if !cmp.Equal(got, want) {
				t.Errorf("unexpected value: got: %v, want: %v", got, want)
			}
		})
	}
}

func TestDockerdClient_HostGatewayInterfaceAddr(t *testing.T) {
	tests := []struct {
		name string
		rt   Runtime
		want string
	}{
		{
			name: "docker desktop",
			rt:   RuntimeDockerdDockerDesktop,
			want: "127.0.0.1",
		},
		{
			name: "docker engine",
			rt:   RuntimeDockerd,
			want: bridgeAddr.IP.String(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cli, err := newTestDockerdClient(t, tt.rt, defaultAPITestdata)
			if err != nil {
				t.Fatalf("new test client: %v", err)
			}
			defer cli.Close()

			got, err := cli.HostGatewayInterfaceAddr()
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if got != tt.want {
				t.Errorf("unexpected value: got: %v, want: %v", got, tt.want)
			}
		})
	}
}

type testDockerdClient struct {
	DockerdClient
	srv *httptest.Server
}

func newTestDockerdClient(t *testing.T, rt Runtime, td apiTestdata) (testDockerdClient, error) {
	srv := httptest.NewServer(testAPI{testdata: td})

	t.Setenv("DOCKER_HOST", "tcp://"+srv.Listener.Addr().String())

	cli, err := NewDockerdClient(rt)
	if err != nil {
		srv.Close()
		return testDockerdClient{}, fmt.Errorf("new client: %w", err)
	}

	tdc := testDockerdClient{
		DockerdClient: cli,
		srv:           srv,
	}
	return tdc, nil
}

func (tdc testDockerdClient) Close() error {
	tdc.srv.Close()
	return tdc.DockerdClient.Close()
}

type testAPI struct {
	testdata apiTestdata
}

var routeRegexp = regexp.MustCompile(`^/v\d+\.\d+(/.*)$`)

func (api testAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m := routeRegexp.FindStringSubmatch(r.URL.Path)
	if m == nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	endpoint := m[1]

	if r.Method != "GET" {
		http.Error(w, "not implemented", http.StatusNotImplemented)
		return
	}

	switch {
	case strings.HasPrefix(endpoint, "/networks/"):
		api.handleNetworks(w, r, strings.TrimPrefix(endpoint, "/networks/"))
	case endpoint == "/info":
		api.handleInfo(w, r)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

type apiTestdata struct {
	networks map[string]networkTestdata
	system   systemTestdata
}

type networkTestdata struct {
	cfgs          []ipamConfig
	gateways      []*net.IPNet
	bridgeGateway *net.IPNet
}

type network struct {
	IPAM ipam `json:"IPAM"`
}

type ipam struct {
	Config []ipamConfig `json:"Config"`
}

type ipamConfig struct {
	Subnet  string `json:"Subnet"`
	Gateway string `json:"Gateway"`
}

func (api testAPI) handleNetworks(w http.ResponseWriter, _ *http.Request, name string) {
	td, ok := api.testdata.networks[name]
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	net := network{IPAM: ipam{Config: td.cfgs}}
	if err := json.NewEncoder(w).Encode(net); err != nil {
		http.Error(w, fmt.Sprintf("marshal: %v", err), http.StatusInternalServerError)
	}
}

type systemTestdata struct {
	id string
}

type info struct {
	ID string `json:"ID"`
}

func (api testAPI) handleInfo(w http.ResponseWriter, _ *http.Request) {
	net := info{ID: api.testdata.system.id}
	if err := json.NewEncoder(w).Encode(net); err != nil {
		http.Error(w, fmt.Sprintf("marshal: %v", err), http.StatusInternalServerError)
	}
}
