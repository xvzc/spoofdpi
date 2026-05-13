//go:build !darwin

package socks5

import (
	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/packet"
)

const StateFile = ""

type socks5SystemNetworkStub struct{}

func NewSOCKS5SystemNetwork(
	logger zerolog.Logger,
	defaultRoute *packet.Route,
) SOCKS5SystemNetwork {
	return &socks5SystemNetworkStub{}
}

func (n *socks5SystemNetworkStub) DefaultRoute() *packet.Route {
	return nil
}

func (n *socks5SystemNetworkStub) BuildJobs(
	_ uint16,
	_ string,
) ([]netutil.NetworkJob, error) {
	return nil, nil
}
