//go:build darwin

package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"

	"github.com/xvzc/spoofdpi/internal/executil"
	"github.com/xvzc/spoofdpi/internal/netutil"
)

// SetupSystemProxy serves a PAC file that routes traffic through pacDirective
// (e.g. "PROXY 127.0.0.1:8080") and saves the jobs that point the network
// service of the default interface at it to stateFile. The PAC server is
// closed when ctx is done.
func SetupSystemProxy(
	ctx context.Context,
	pacDirective string,
	stateFile string,
) error {
	pacContent := fmt.Sprintf(
		"function FindProxyForURL(url, host) {\n    return \"%s; DIRECT\";\n}",
		pacDirective,
	)
	pacURL, pac, err := runPACServer(pacContent)
	if err != nil {
		return fmt.Errorf("error creating pac server: %w", err)
	}
	jobs, err := buildSysProxyJobs(pacURL)
	if err != nil {
		_ = pac.Close()
		return err
	}
	if err := SaveJobs(stateFile, jobs); err != nil {
		_ = pac.Close()
		return fmt.Errorf("failed to save state: %w", err)
	}
	go func() { <-ctx.Done(); _ = pac.Close() }()
	return nil
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

func buildSysProxyJobs(pacURL string) ([]NetworkJob, error) {
	iface, _, err := netutil.DiscoverInterface()
	if err != nil {
		return nil, err
	}

	service, err := getNetworkServiceFromInterface(iface.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to get network service: %w", err)
	}

	var jobs []NetworkJob

	jobs = append(jobs, NetworkJob{
		Description: "set auto proxy URL",
		Apply: fmt.Sprintf(
			"networksetup -setautoproxyurl %s %s",
			executil.Quote(service),
			pacURL,
		),
		Reset: fmt.Sprintf(
			"networksetup -setautoproxystate %s off",
			executil.Quote(service),
		),
	})

	jobs = append(jobs, NetworkJob{
		Description: "enable proxy auto discovery",
		Apply: fmt.Sprintf(
			"networksetup -setproxyautodiscovery %s on",
			executil.Quote(service),
		),
		Reset: fmt.Sprintf(
			"networksetup -setproxyautodiscovery %s off",
			executil.Quote(service),
		),
	})

	return jobs, nil
}
