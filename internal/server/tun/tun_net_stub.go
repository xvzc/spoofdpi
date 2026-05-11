//go:build !darwin && !linux && !freebsd

package tun

import (
	"net"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"golang.zx2c4.com/wireguard/tun"
)

const StateFile = ""

func (n *tunSystemNetworkStub) BuildJobs() ([]netutil.NetworkJob, error) {
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
	defaultRoute *netutil.Route,
	fibID int,
) (TUNSystemNetwork, error) {
	return &tunSystemNetworkStub{logger: logger}, nil
}

func (n *tunSystemNetworkStub) TunDevice() tun.Device {
	return nil
}

func (n *tunSystemNetworkStub) DefaultRoute() *netutil.Route {
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
