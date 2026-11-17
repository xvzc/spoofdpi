//go:build !darwin

package socks5

import (
	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/netutil"
)

const StateFile = ""

type socks5SystemNetworkStub struct{}

func NewSOCKS5SystemNetwork(
	logger zerolog.Logger,
	defaultRoute *netutil.Route,
) SOCKS5SystemNetwork {
	return &socks5SystemNetworkStub{}
}

func (n *socks5SystemNetworkStub) DefaultRoute() *netutil.Route {
	return nil
}

func (n *socks5SystemNetworkStub) BuildJobs(
	_ uint16,
	_ string,
) ([]netutil.NetworkJob, error) {
	return nil, nil
}
