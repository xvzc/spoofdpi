//go:build !darwin

package http

import (
	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/server"
)

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

type httpStateStub struct{}

func createState(
	defaultRoute *netutil.Route,
	port uint16,
	pacURL string,
) (*httpStateStub, error) {
	return &httpStateStub{}, nil
}

func buildJobs(state *httpStateStub) []server.NetworkJob {
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
