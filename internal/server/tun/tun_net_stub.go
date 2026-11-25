//go:build !darwin && !linux && !freebsd

package tun

import (
	"net"
	"syscall"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/route"
	"github.com/xvzc/spoofdpi/internal/server"
	"golang.zx2c4.com/wireguard/tun"
)

const StateFile = ""

func (n *tunSystemNetworkStub) BuildJobs() ([]server.NetworkJob, error) {
	return nil, nil
}

func createTunDevice() (tun.Device, error) {
	return nil, nil
}

// tunSystemNetworkStub implements TUNSystemNetwork for unsupported platforms
type tunSystemNetworkStub struct {
	logger zerolog.Logger
}

// NewTUNSystemNetwork creates a new TUNSystemNetwork for TUN mode on unsupported platforms
func NewTUNSystemNetwork(
	logger zerolog.Logger,
	defaultRoute *route.Route,
	fibID int,
	ipv6Enabled bool,
) (TUNSystemNetwork, error) {
	return &tunSystemNetworkStub{logger: logger}, nil
}

func (n *tunSystemNetworkStub) TunDevice() tun.Device {
	return nil
}

func (n *tunSystemNetworkStub) FIBID() int {
	return 1
}

func (n *tunSystemNetworkStub) BindDialer(
	dialer *net.Dialer,
	network string,
	targetIP net.IP,
) error {
	return nil
}

// EgressControl returns nil: TUN mode is not supported here.
func EgressControl(
	*route.Route,
	int,
) func(network, address string, c syscall.RawConn) error {
	return nil
}
