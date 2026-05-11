//go:build !darwin

package socks5

import (
	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/server"
)

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

type socks5StateStub struct{}

func createState(
	defaultRoute *netutil.Route,
	port uint16,
	pacURL string,
) (*socks5StateStub, error) {
	return &socks5StateStub{}, nil
}

func buildJobs(state *socks5StateStub) []server.NetworkJob {
	return nil
}

func saveState(jobs []server.NetworkJob) error {
	return nil
}

func loadState() ([]server.NetworkJob, bool, error) {
	return nil, false, nil
}

func deleteState() error {
	return nil
}
