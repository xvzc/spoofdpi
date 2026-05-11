//go:build darwin

package http

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/executil"
	"github.com/xvzc/spoofdpi/internal/netutil"
)

const StateFile = "/tmp/spoofdpi.http.darwin.state"

type httpNetworkInfoDarwin struct {
	Service string
	PACURL  string
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

func collectNetworkInfo(
	defaultRoute *netutil.Route, pacURL string,
) (*httpNetworkInfoDarwin, error) {
	service, err := getNetworkServiceFromInterface(defaultRoute.Iface.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to get network service: %w", err)
	}

	return &httpNetworkInfoDarwin{ //exhaustruct:enforce
		Service: service,
		PACURL:  pacURL,
	}, nil
}

func (n *httpSystemNetworkDarwin) BuildJobs(
	port uint16,
	pacURL string,
) ([]netutil.NetworkJob, error) {
	info, err := collectNetworkInfo(n.defaultRoute, pacURL)
	if err != nil {
		return nil, err
	}

	var jobs []netutil.NetworkJob

	jobs = append(jobs, netutil.NetworkJob{
		Description: "set auto proxy URL",
		Apply: fmt.Sprintf(
			"networksetup -setautoproxyurl %s %s",
			info.Service,
			info.PACURL,
		),
		Reset: fmt.Sprintf("networksetup -setautoproxystate %s off", info.Service),
	})

	jobs = append(jobs, netutil.NetworkJob{
		Description: "enable proxy auto discovery",
		Apply:       fmt.Sprintf("networksetup -setproxyautodiscovery %s on", info.Service),
		Reset: fmt.Sprintf(
			"networksetup -setproxyautodiscovery %s off",
			info.Service,
		),
	})

	return jobs, nil
}
