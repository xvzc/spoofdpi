//go:build darwin

package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/executil"
	"github.com/xvzc/spoofdpi/internal/route"
)

// SetupSystemProxy serves a PAC file that routes traffic through pacDirective
// (e.g. "PROXY 127.0.0.1:8080") and returns the jobs that point the network
// service of the default interface at it. The PAC server is closed when ctx
// is done.
func SetupSystemProxy(
	ctx context.Context,
	logger zerolog.Logger,
	pacDirective string,
) ([]NetworkJob, error) {
	pacContent := fmt.Sprintf(
		"function FindProxyForURL(url, host) {\n    return \"%s; DIRECT\";\n}",
		pacDirective,
	)
	pacURL, pac, err := runPACServer(pacContent)
	if err != nil {
		return nil, fmt.Errorf("error creating pac server: %w", err)
	}
	jobs, err := buildSysProxyJobs(logger, pacURL)
	if err != nil {
		_ = pac.Close()
		return nil, err
	}
	go func() { <-ctx.Done(); _ = pac.Close() }()
	return jobs, nil
}

func runPACServer(content string) (string, *http.Server, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(content))
	})

	server := &http.Server{
		Handler: mux,
	}

	go func() {
		_ = server.Serve(listener)
	}()

	addr := listener.Addr().(*net.TCPAddr)
	url := fmt.Sprintf("http://127.0.0.1:%d/proxy.pac", addr.Port)

	return url, server, nil
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

func buildSysProxyJobs(logger zerolog.Logger, pacURL string) ([]NetworkJob, error) {
	// A full-tunnel VPN holds the primary default; the network service to
	// configure is still the one of the physical interface.
	iface, fallback, err := route.PrimaryInterface()
	if err != nil {
		return nil, err
	}
	if fallback.DefaultsErr != nil {
		logger.Debug().
			Err(fallback.DefaultsErr).
			Str("iface", iface.Name).
			Msg("cannot read the default routes; using the primary default")
	}
	if skipped := fallback.Skipped; skipped != nil {
		logger.Debug().
			Str("primary", skipped.Name).
			Str("link", skipped.Kind.String()).
			Str("iface", iface.Name).
			Msg("primary default is not physical; using the physical default")
	}

	service, err := getNetworkServiceFromInterface(iface.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to get network service: %w", err)
	}

	return sysProxyJobs(service, pacURL), nil
}

// sysProxyJobs returns the jobs that point the network service named service
// at the PAC file at pacURL.
func sysProxyJobs(service, pacURL string) []NetworkJob {
	var jobs []NetworkJob

	jobs = append(jobs, NetworkJob{
		Description: "set auto proxy URL",
		Apply:       CommandAction{"networksetup", "-setautoproxyurl", service, pacURL},
		Reset:       CommandAction{"networksetup", "-setautoproxystate", service, "off"},
	})

	jobs = append(jobs, NetworkJob{
		Description: "enable proxy auto discovery",
		Apply:       CommandAction{"networksetup", "-setproxyautodiscovery", service, "on"},
		Reset: CommandAction{
			"networksetup",
			"-setproxyautodiscovery",
			service,
			"off",
		},
	})

	return jobs
}

// CleanSystemProxyLeftovers turns off the auto proxy configuration that an
// earlier run in a proxy mode left on when it ended without restoring it,
// such as on a crash. It runs at startup in every mode and never fails the
// start.
//
// It finds nothing yet, so nothing recovers from a crash: the system proxy
// of such a run stays on until it is turned off by hand.
func CleanSystemProxyLeftovers(logger zerolog.Logger) {
	// TODO(S7): find the network services whose auto proxy URL points at a
	// spoofdpi PAC server that no longer answers.
}

// CheckSystemProxyLeftoversAfterReset warns about the auto proxy
// configuration of this run that is still on after ResetJobs restored the
// network configuration, which points to a bug in a job's Reset. It turns
// nothing off.
func CheckSystemProxyLeftoversAfterReset(logger zerolog.Logger) {
	// TODO(S7): look for what this run turned on.
}
