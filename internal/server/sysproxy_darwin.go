//go:build darwin

package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

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
		pacMarkerComment+"\nfunction FindProxyForURL(url, host) {\n    return \"%s; DIRECT\";\n}",
		pacDirective,
	)
	pacURL, pac, err := runPACServer(pacContent)
	if err != nil {
		return nil, fmt.Errorf("error creating pac server: %w", err)
	}
	jobs, service, err := buildSysProxyJobs(logger, pacURL)
	if err != nil {
		_ = pac.Close()
		return nil, err
	}
	setThisRunProxy(service, pacURL)
	go func() { <-ctx.Done(); _ = pac.Close() }()
	return jobs, nil
}

func runPACServer(content string) (string, *http.Server, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}

	mux := http.NewServeMux()
	servePAC := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
		w.Header().Set(pacMarkerHeader, pacMarkerValue)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(content))
	}
	mux.HandleFunc("/spoofdpi.pac", servePAC)
	// Older versions served /proxy.pac, which a crashed old run may still
	// point at.
	mux.HandleFunc("/proxy.pac", servePAC)

	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		_ = server.Serve(listener)
	}()

	addr := listener.Addr().(*net.TCPAddr)
	url := fmt.Sprintf("http://127.0.0.1:%d/spoofdpi.pac", addr.Port)

	return url, server, nil
}

// The PAC server marks its responses so that a later run can tell a live
// spoofdpi instance from another server on the same port.
const (
	pacMarkerHeader  = "X-Spoofdpi"
	pacMarkerValue   = "pac"
	pacMarkerComment = "// spoofdpi"
)

// runNetworksetup runs networksetup with args, without a shell, and returns
// its combined output. Tests replace it.
var runNetworksetup = func(args ...string) (string, error) {
	return executil.Run("networksetup", args...)
}

// thisRunProxy is the network service and PAC URL that this run set up, for
// CheckSystemProxyLeftoversAfterReset.
var thisRunProxy struct {
	sync.Mutex
	service, pacURL string
}

func setThisRunProxy(service, pacURL string) {
	thisRunProxy.Lock()
	defer thisRunProxy.Unlock()
	thisRunProxy.service, thisRunProxy.pacURL = service, pacURL
}

func getNetworkServiceFromInterface(ifaceName string) (string, error) {
	out, err := runNetworksetup("-listnetworkserviceorder")
	if err != nil {
		return "", err
	}

	re := regexp.MustCompile(
		fmt.Sprintf(`\(\d+\)\s+(.*)\s+\(Hardware Port:.*Device:\s+%s\)`, ifaceName),
	)
	match := re.FindStringSubmatch(out)

	if len(match) < 2 {
		return "", fmt.Errorf("no network service found for interface: %s", ifaceName)
	}

	return strings.TrimSpace(match[1]), nil
}

func buildSysProxyJobs(
	logger zerolog.Logger,
	pacURL string,
) ([]NetworkJob, string, error) {
	// A full-tunnel VPN holds the primary default; the network service to
	// configure is still the one of the physical interface.
	iface, fallback, err := route.PrimaryInterface()
	if err != nil {
		return nil, "", err
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
		return nil, "", fmt.Errorf("failed to get network service: %w", err)
	}

	return sysProxyJobs(service, pacURL), service, nil
}

// sysProxyJobs returns the jobs that point the network service named service
// at the PAC file at pacURL.
func sysProxyJobs(service, pacURL string) []NetworkJob {
	return []NetworkJob{{
		Description: "set auto proxy URL",
		Apply:       CommandAction{"networksetup", "-setautoproxyurl", service, pacURL},
		Reset:       CommandAction{"networksetup", "-setautoproxystate", service, "off"},
	}}
}

// CleanSystemProxyLeftovers turns off the auto proxy configuration that an
// earlier run in a proxy mode left on when it ended without restoring it,
// such as on a crash. It runs at startup in every mode and never fails the
// start.
//
// Only an enabled auto proxy URL of a spoofdpi PAC server that refuses
// connections is turned off. A live instance, another server on the port,
// and a PAC server that does not answer in time are left as they are.
func CleanSystemProxyLeftovers(logger zerolog.Logger) {
	services, err := listNetworkServices()
	if err != nil {
		logger.Warn().
			Err(err).
			Msg("cannot list network services to look for leftover system proxy")
		return
	}

	var leftovers []Leftover
	for _, service := range services {
		cfg, err := getAutoProxy(service)
		if err != nil {
			logger.Warn().Err(err).Str("service", service).
				Msg("cannot read the auto proxy configuration")
			continue
		}
		if !cfg.Enabled || !spoofdpiPACURL.MatchString(cfg.URL) {
			continue
		}
		switch state := probePAC(cfg.URL); state.kind {
		case pacLive:
			logger.Info().Str("service", service).Str("url", cfg.URL).
				Msg("system proxy belongs to a running spoofdpi; leaving it")
		case pacDead:
			leftovers = append(leftovers, autoProxyLeftover(service, cfg.URL, ""))
		default:
			leftovers = append(leftovers, autoProxyLeftover(service, cfg.URL, state.reason))
		}
	}
	RemoveLeftovers(logger, leftovers)
}

// CheckSystemProxyLeftoversAfterReset warns about the auto proxy
// configuration of this run that is still on after ResetJobs restored the
// network configuration, which points to a bug in a job's Reset. It turns
// nothing off.
func CheckSystemProxyLeftoversAfterReset(logger zerolog.Logger) {
	thisRunProxy.Lock()
	service, pacURL := thisRunProxy.service, thisRunProxy.pacURL
	thisRunProxy.Unlock()
	if service == "" {
		return
	}

	cfg, err := getAutoProxy(service)
	if err != nil {
		logger.Warn().Err(err).Str("service", service).
			Msg("cannot read the auto proxy configuration after restoring it")
		return
	}
	if cfg.Enabled && cfg.URL == pacURL {
		WarnLeftoversAfterReset(
			logger,
			[]Leftover{autoProxyLeftover(service, pacURL, "")},
		)
	}
}

// autoProxyLeftover describes the enabled auto proxy URL of service. It is
// removable only when keepReason is empty: otherwise keepReason tells why it
// may belong to a live instance or to another tool, and it is left as it is.
func autoProxyLeftover(service, url, keepReason string) Leftover {
	description := fmt.Sprintf("auto proxy URL %s of network service %q", url, service)
	if keepReason != "" {
		description += ": " + keepReason
	}
	l := Leftover{
		Description:   description,
		ManualCommand: "networksetup -setautoproxystate " + shellQuote(service) + " off",
	}
	if keepReason == "" {
		l.Remove = func() error {
			if _, err := runNetworksetupChecked(
				"-setautoproxystate",
				service,
				"off",
			); err != nil {
				return err
			}
			cfg, err := getAutoProxy(service)
			if err != nil {
				return err
			}
			if cfg.Enabled {
				return fmt.Errorf("auto proxy of %q is still enabled", service)
			}
			return nil
		}
	}
	return l
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// spoofdpiPACURL matches the PAC URL of a spoofdpi run. The older
// /proxy.pac path is still recognized.
var spoofdpiPACURL = regexp.MustCompile(
	`^http://127\.0\.0\.1:\d+/(spoofdpi|proxy)\.pac$`,
)

type autoProxyConfig struct {
	URL     string
	Enabled bool
}

// parseNetworkServices parses the output of networksetup
// -listallnetworkservices: a header line, then one service per line, with
// disabled services prefixed by an asterisk.
func parseNetworkServices(out string) []string {
	var services []string
	for i, line := range strings.Split(out, "\n") {
		if i == 0 && strings.HasPrefix(line, "An asterisk") {
			continue
		}
		name := strings.TrimPrefix(strings.TrimRight(line, "\r"), "*")
		if strings.TrimSpace(name) == "" {
			continue
		}
		services = append(services, name)
	}
	return services
}

// parseAutoProxy parses the output of networksetup -getautoproxyurl.
func parseAutoProxy(out string) autoProxyConfig {
	var cfg autoProxyConfig
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.TrimSpace(key) {
		case "URL":
			cfg.URL = value
		case "Enabled":
			cfg.Enabled = value == "Yes"
		}
	}
	return cfg
}

// runNetworksetupChecked runs networksetup and treats an exit status of 0
// with output starting with "** Error" as a failure too, because
// networksetup reports some errors that way.
func runNetworksetupChecked(args ...string) (string, error) {
	out, err := runNetworksetup(args...)
	if err == nil && strings.HasPrefix(strings.TrimSpace(out), "** Error") {
		err = errors.New("networksetup failed")
	}
	if err != nil {
		return out, fmt.Errorf("%w: %s", err, strings.TrimSpace(out))
	}
	return out, nil
}

func listNetworkServices() ([]string, error) {
	out, err := runNetworksetup("-listallnetworkservices")
	if err != nil {
		return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(out))
	}
	return parseNetworkServices(out), nil
}

func getAutoProxy(service string) (autoProxyConfig, error) {
	out, err := runNetworksetupChecked("-getautoproxyurl", service)
	if err != nil {
		return autoProxyConfig{}, err
	}
	return parseAutoProxy(out), nil
}

type pacKind int

const (
	// pacDead: the connection was refused, so no server listens there.
	pacDead pacKind = iota
	// pacLive: a spoofdpi PAC server answered.
	pacLive
	// pacUnknown: something else answered, or the state is unclear.
	pacUnknown
)

type pacState struct {
	kind pacKind
	// reason tells why the state is pacUnknown.
	reason string
}

const (
	pacProbeTimeout   = time.Second
	pacProbeBodyLimit = 512
)

// probePAC asks the PAC server at url whether it is a live spoofdpi. Only a
// refused connection counts as dead; a timeout or any other error leaves the
// state unknown.
func probePAC(url string) pacState {
	client := &http.Client{
		Timeout: pacProbeTimeout,
		// The proxy settings of the environment must not route the probe, and
		// the connection is not reused.
		Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(url)
	if err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) {
			return pacState{kind: pacDead}
		}
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return pacState{
				kind:   pacUnknown,
				reason: fmt.Sprintf("PAC server did not answer within %s", pacProbeTimeout),
			}
		}
		return pacState{
			kind:   pacUnknown,
			reason: "PAC server not reachable: " + err.Error(),
		}
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return pacState{
			kind:   pacUnknown,
			reason: "port answered by a non-spoofdpi server: " + resp.Status,
		}
	}
	if resp.Header.Get(pacMarkerHeader) == pacMarkerValue {
		return pacState{kind: pacLive}
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, pacProbeBodyLimit))
	if strings.HasPrefix(string(body), pacMarkerComment) {
		return pacState{kind: pacLive}
	}
	return pacState{
		kind: pacUnknown,
		reason: "answered without the spoofdpi marker " +
			"(possibly an older spoofdpi still running)",
	}
}
