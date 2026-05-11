//go:build darwin

package socks5

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

const socks5StateFile = "/tmp/spoofdpi.socks5.darwin.state"

type socks5StateDarwin struct {
	Service    string `json:"service"`
	ServerPort uint16 `json:"serverPort"`
	ProxyType  string `json:"proxyType"`
	PACURL     string `json:"pacURL"`
}

type socks5SystemNetworkDarwin struct {
	logger       zerolog.Logger
	defaultRoute *netutil.Route
}

func NewSOCKS5SystemNetwork(
	logger zerolog.Logger,
	defaultRoute *netutil.Route,
) SOCKS5SystemNetwork {
	return &socks5SystemNetworkDarwin{
		logger:       logger,
		defaultRoute: defaultRoute,
	}
}

func (n *socks5SystemNetworkDarwin) DefaultRoute() *netutil.Route {
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
) (*socks5StateDarwin, error) {
	ifaceName := defaultRoute.Iface.Name
	service, err := getNetworkServiceFromInterface(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get network service: %w", err)
	}

	return &socks5StateDarwin{
		Service:    service,
		ServerPort: serverPort,
		ProxyType:  "SOCKS5",
		PACURL:     pacURL,
	}, nil
}

func buildJobs(state *socks5StateDarwin) []server.NetworkJob {
	var jobs []server.NetworkJob

	jobs = append(jobs, server.NetworkJob{
		Description: "set auto proxy URL",
		Up: []string{
			fmt.Sprintf("networksetup -setautoproxyurl %s %s", state.Service, state.PACURL),
		},
		Down: []string{
			fmt.Sprintf("networksetup -setautoproxystate %s off", state.Service),
		},
	})

	jobs = append(jobs, server.NetworkJob{
		Description: "enable proxy auto discovery",
		Up: []string{
			fmt.Sprintf("networksetup -setproxyautodiscovery %s on", state.Service),
		},
		Down: []string{
			fmt.Sprintf("networksetup -setproxyautodiscovery %s off", state.Service),
		},
	})

	return jobs
}

func saveState(jobs []server.NetworkJob) error {
	type state struct {
		Jobs      []server.NetworkJob `json:"jobs"`
		CreatedAt time.Time           `json:"createdAt"`
	}
	data, err := json.MarshalIndent(state{Jobs: jobs, CreatedAt: time.Now()}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(socks5StateFile, data, 0o644)
}

func loadState() ([]server.NetworkJob, bool, error) {
	type state struct {
		Jobs []server.NetworkJob `json:"jobs"`
	}
	data, err := os.ReadFile(socks5StateFile)
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
	if err := os.Remove(socks5StateFile); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
