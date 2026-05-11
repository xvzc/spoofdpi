//go:build !darwin

package http

import (
	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/netutil"
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
) ([]netutil.NetworkJob, error) {
	return nil, nil
}
