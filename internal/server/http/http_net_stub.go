//go:build !darwin

package http

import (
	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/server"
)

const StateFile = ""

type httpSystemNetworkStub struct{}

func NewHTTPSystemNetwork(
	logger zerolog.Logger,
	defaultRoute *netutil.Route,
) HTTPSystemNetwork {
	return &httpSystemNetworkStub{}
}

func (n *httpSystemNetworkStub) DefaultRoute() *netutil.Route {
	return nil
}

func (n *httpSystemNetworkStub) BuildJobs(
	_ uint16,
	_ string,
) ([]server.NetworkJob, error) {
	return nil, nil
}
