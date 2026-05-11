//go:build darwin

package http

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/executil"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/server"
)

const httpStateFile = "/tmp/spoofdpi.http.darwin.state"

type httpStateDarwin struct {
	Service   string `json:"service"`
	Port      uint16 `json:"port"`
	ProxyType string `json:"proxyType"`
	PACURL    string `json:"pacURL"`
}

type httpSystemNetworkDarwin struct {
	logger       zerolog.Logger
	defaultRoute *netutil.Route
}

func NewHTTPSystemNetwork(
	logger zerolog.Logger,
	defaultRoute *netutil.Route,
) HTTPSystemNetwork {
	return &httpSystemNetworkDarwin{
		logger:       logger,
		defaultRoute: defaultRoute,
	}
}

func (n *httpSystemNetworkDarwin) DefaultRoute() *netutil.Route {
	return n.defaultRoute
}

func getNetworkServiceFromInterface(ifaceName string) (string, error) {
	out, err := executil.Commandf("networksetup -listnetworkserviceorder")
	if err != nil {
		return "", err
	}

	re := regexp.MustCompile(
		fmt.Sprintf(`\(\d+\)\s+(.*)\s+\(Hardware Port:.*Device:\s+%s\)`, ifaceName),
	)
	match := re.FindStringSubmatch(string(out))

	if len(match) < 2 {
		return "", fmt.Errorf("no network service found for interface: %s", ifaceName)
	}

	return strings.TrimSpace(match[1]), nil
}

func createState(
	defaultRoute *netutil.Route, serverPort uint16, pacURL string,
) (*httpStateDarwin, error) {
	ifaceName := defaultRoute.Iface.Name
	service, err := getNetworkServiceFromInterface(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get network service: %w", err)
	}

	return &httpStateDarwin{
		Service:   service,
		Port:      serverPort,
		ProxyType: "PROXY",
		PACURL:    pacURL,
	}, nil
}

func buildJobs(state *httpStateDarwin) []server.NetworkJob {
	return []server.NetworkJob{
		{
			Description: "set auto proxy URL",
			Up: []string{
				fmt.Sprintf("networksetup -setautoproxyurl %s %s", state.Service, state.PACURL),
			},
			Down: []string{
				fmt.Sprintf("networksetup -setautoproxystate %s off", state.Service),
			},
		},
		{
			Description: "enable proxy auto discovery",
			Up: []string{
				fmt.Sprintf("networksetup -setproxyautodiscovery %s on", state.Service),
			},
			Down: []string{
				fmt.Sprintf("networksetup -setproxyautodiscovery %s off", state.Service),
			},
		},
	}
}

func saveState(jobs []server.NetworkJob) error {
	type state struct {
		Jobs      []server.NetworkJob `json:"jobs"`
		CreatedAt time.Time           `json:"createdAt"`
	}
	data, err := json.Marshal(state{Jobs: jobs, CreatedAt: time.Now()})
	if err != nil {
		return err
	}
	return os.WriteFile(httpStateFile, data, 0o644)
}

func loadState() ([]server.NetworkJob, bool, error) {
	type state struct {
		Jobs []server.NetworkJob `json:"jobs"`
	}
	data, err := os.ReadFile(httpStateFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	var s state
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, false, err
	}
	return s.Jobs, true, nil
}

func deleteState() error {
	if err := os.Remove(httpStateFile); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
