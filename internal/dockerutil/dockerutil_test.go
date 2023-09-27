// Copyright 2023 Adevinta

package dockerutil

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

	"github.com/docker/docker/client"
	"github.com/google/go-cmp/cmp"
)

var (
	bridgeCfgs = []ipamConfig{{Subnet: "172.17.0.0/16", Gateway: "172.17.0.1"}}
	bridgeAddr = &net.IPNet{IP: net.ParseIP("172.17.0.1"), Mask: net.CIDRMask(16, 32)}

	defaultAPITestdata = apiTestdata{
		networks: map[string]networkTestdata{
			DefaultBridgeNetwork: {
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

func TestNewAPIClient_host(t *testing.T) {
	const dockerHost = "tcp://example.com:1234"

	t.Setenv("DOCKER_CONFIG", "testdata/certs")
	t.Setenv("DOCKER_HOST", dockerHost)

	cli, err := NewAPIClient()
	if err != nil {
		t.Fatalf("new API client: %v", err)
	}
	defer cli.Close()

	if dh := cli.DaemonHost(); dh != dockerHost {
		t.Errorf("unexpected daemon host: got: %v, want: %v", dh, dockerHost)
	}
}

func TestNewAPIClient_tls(t *testing.T) {
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

			cli, err := NewAPIClient()
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

func TestGateways(t *testing.T) {
	tests := []struct {
		name       string
		net        string
		wantNilErr bool
	}{
		{
			name:       "default bridge network",
			net:        DefaultBridgeNetwork,
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
			cli, err := newTestClient(defaultAPITestdata)
			if err != nil {
				t.Fatalf("new test client: %v", err)
			}
			defer cli.Close()

			got, err := Gateways(context.Background(), cli, tt.net)

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

func TestBridgeGateway(t *testing.T) {
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
					DefaultBridgeNetwork: {
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
					DefaultBridgeNetwork: {},
				},
			},
			wantNilErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cli, err := newTestClient(tt.td)
			if err != nil {
				t.Fatalf("new test client: %v", err)
			}
			defer cli.Close()

			got, err := BridgeGateway(cli)

			if (err == nil) != tt.wantNilErr {
				t.Errorf("unexpected error: %v", err)
			}

			want := tt.td.networks[DefaultBridgeNetwork].bridgeGateway
			if !cmp.Equal(got, want) {
				t.Errorf("unexpected value: got: %v, want: %v", got, want)
			}
		})
	}
}

func TestBridgeHost(t *testing.T) {
	tests := []struct {
		name       string
		ifaceAddrs []net.Addr
		want       string
	}{
		{
			name: "docker desktop",
			ifaceAddrs: []net.Addr{
				&net.IPNet{IP: net.ParseIP("1.1.1.1"), Mask: net.CIDRMask(16, 32)},
			},
			want: "127.0.0.1",
		},
		{
			name: "docker engine",
			ifaceAddrs: []net.Addr{
				&net.IPNet{IP: net.ParseIP("1.1.1.1"), Mask: net.CIDRMask(16, 32)},
				bridgeAddr,
			},
			want: bridgeAddr.IP.String(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cli, err := newTestClient(defaultAPITestdata)
			if err != nil {
				t.Fatalf("new test client: %v", err)
			}
			defer cli.Close()

			got, err := bridgeHost(cli, func() ([]net.Addr, error) {
				return tt.ifaceAddrs, nil
			})
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if got != tt.want {
				t.Errorf("unexpected value: got: %v, want: %v", got, tt.want)
			}
		})
	}
}

func TestIsDockerDesktop(t *testing.T) {
	tests := []struct {
		name       string
		ifaceAddrs []net.Addr
		want       bool
	}{
		{
			name: "docker desktop",
			ifaceAddrs: []net.Addr{
				&net.IPNet{IP: net.ParseIP("1.1.1.1"), Mask: net.CIDRMask(16, 32)},
			},
			want: true,
		},
		{
			name: "docker engine",
			ifaceAddrs: []net.Addr{
				&net.IPNet{IP: net.ParseIP("1.1.1.1"), Mask: net.CIDRMask(16, 32)},
				bridgeAddr,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cli, err := newTestClient(defaultAPITestdata)
			if err != nil {
				t.Fatalf("new test client: %v", err)
			}
			defer cli.Close()

			got, err := isDockerDesktop(cli, func() ([]net.Addr, error) {
				return tt.ifaceAddrs, nil
			})
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if got != tt.want {
				t.Errorf("unexpected value: got: %v, want: %v", got, tt.want)
			}
		})
	}
}

func TestIsDockerDesktop_resolver_error(t *testing.T) {
	cli, err := newTestClient(defaultAPITestdata)
	if err != nil {
		t.Fatalf("new test client: %v", err)
	}
	defer cli.Close()

	_, err = isDockerDesktop(cli, func() ([]net.Addr, error) {
		return nil, errors.New("error")
	})
	if err == nil {
		t.Errorf("unexpected nil error")
	}
}

type testClient struct {
	*client.Client
	srv *httptest.Server
}

func newTestClient(td apiTestdata) (testClient, error) {
	srv := httptest.NewServer(testAPI{testdata: td})

	cli, err := client.NewClientWithOpts(client.WithHost(srv.URL))
	if err != nil {
		srv.Close()
		return testClient{}, fmt.Errorf("new client: %w", err)
	}

	mc := testClient{
		Client: cli,
		srv:    srv,
	}
	return mc, nil
}

func (mc testClient) Close() error {
	mc.srv.Close()
	return mc.Client.Close()
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

func (api testAPI) handleNetworks(w http.ResponseWriter, r *http.Request, name string) {
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

func (api testAPI) handleInfo(w http.ResponseWriter, r *http.Request) {
	net := info{ID: api.testdata.system.id}
	if err := json.NewEncoder(w).Encode(net); err != nil {
		http.Error(w, fmt.Sprintf("marshal: %v", err), http.StatusInternalServerError)
	}
}
