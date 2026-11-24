package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/desync"
	"github.com/xvzc/spoofdpi/internal/dns"
	"github.com/xvzc/spoofdpi/internal/inject"
	"github.com/xvzc/spoofdpi/internal/logging"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/packet"
	"github.com/xvzc/spoofdpi/internal/rule"
	"github.com/xvzc/spoofdpi/internal/server"
	"github.com/xvzc/spoofdpi/internal/server/http"
	"github.com/xvzc/spoofdpi/internal/server/socks5"
	"github.com/xvzc/spoofdpi/internal/server/tun"
)

// Version and commit are set at build time.
var (
	version = "dev"
	commit  = "unknown"
	build   = "unknown"
)

type SwitchableWriter struct {
	// target is a pointer to an interface, or just the interface itself.
	// We use a pointer to the interface for direct updates.
	target io.Writer
}

func (sw *SwitchableWriter) SetWriter(w io.Writer) {
	// Update the underlying value that the pointer references
	sw.target = w
}

func (sw *SwitchableWriter) Write(p []byte) (n int, err error) {
	// Access the current writer through the pointer
	return sw.target.Write(p)
}

type DelayedWriter struct {
	writer io.Writer
	delay  time.Duration
}

// DelayedWriter is stateless, so value receiver is technically fine,
// but pointer receiver is preferred for consistency in Go.
func (dw *DelayedWriter) Write(p []byte) (n int, err error) {
	if dw.delay > 0 {
		time.Sleep(dw.delay)
	}
	return dw.writer.Write(p)
}

func main() {
	selected := newCommandRegistry(runApp, os.Executable).selectCommand(os.Args)
	if err := selected.cmd.Run(context.Background(), selected.args); err != nil {
		if selected.runsServer {
			fmt.Println("application failed to start")
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "%s: %v\n", selected.cmd.Name, err)
		// An interrupted livetest or probe exits with the signal's status.
		var status interface{ ExitStatus() int }
		if errors.As(err, &status) {
			os.Exit(status.ExitStatus())
		}
		os.Exit(1)
	}
}

func runApp(mainctx context.Context, configDir string, cfg *config.Config) (err error) {
	appctx, cancel := signal.NotifyContext(
		mainctx,
		syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP,
	)
	defer cancel()
	// Once shutdown starts, a second signal gets its default behavior and
	// ends the process at once.
	context.AfterFunc(appctx, cancel)

	var writer io.Writer
	// Channel to capture critical TUI execution failures
	if !cfg.App.NoTUI {
		if err := startTUI(cancel); err != nil {
			return fmt.Errorf("failed to start tui: %w", err)
		}
		writer = TUIWriter{}
	} else {
		writer = os.Stdout
	}

	dw := &DelayedWriter{
		writer: writer,
		delay:  29 * time.Millisecond,
	}
	sw := &SwitchableWriter{target: dw}

	logging.SetGlobalLogger(appctx, cfg.App.LogLevel, sw)
	logger := log.Logger.With().Ctx(appctx).Logger()

	// In TUI mode the alt-screen has already been claimed by startTUI.
	// Letting a setup error bubble up via `return err` would land in
	// main's fmt.Println + os.Exit(1) path, which tears down the alt
	// screen before the user can read what went wrong.
	//
	// Catch the error here instead: log it through the configured logger
	// so it shows up in the TUI, park on appctx until the user dismisses
	// with Ctrl+C, and clear `err` so main exits cleanly.
	//
	// Headless mode keeps the original behavior — the error propagates
	// to main, which prints "application failed to start" to stderr and
	// exits with status 1.
	defer func() {
		if err == nil || cfg.App.NoTUI {
			return
		}
		logger.Error().Err(err).Msg("application failed to start")
		<-appctx.Done()
		err = nil
	}()

	logger.Info().Str("version", version).Msg("spoofdpi")
	// livetest reads these two messages, and the dir field, to report the
	// config file its baseline case loaded (internal/livetest/case.go).
	if configDir != "" {
		logger.Info().
			Str("dir", configDir).
			Msgf("loaded config file")
	} else {
		logger.Warn().
			Msg("config file not found")
		logger.Warn().
			Msg(" please try 'sudo -E spoofdpi' if you expect a configuration to be loaded")
	}

	for _, m := range config.WarnMsgs {
		logger.Warn().Msg(m)
	}

	logger.Info().Str("mode", cfg.App.Mode.String()).Msgf("app")

	srv, err := createServer(appctx, logger, cfg)
	if err != nil {
		return fmt.Errorf("create server: %w", err)
	}

	logger.Info().Msg("tls info")
	logger.Info().
		Str("split-mode", cfg.HTTPS.SplitMode.String()).
		Uint8("chunk-size", uint8(cfg.HTTPS.ChunkSize)).
		Bool("disorder", cfg.HTTPS.Disorder).
		Msg(" split")

	logger.Info().
		Uint8("preflight", uint8(cfg.HTTPS.FakePreflight)).
		Uint8("stutter", uint8(cfg.HTTPS.FakeStutter)).
		Int64("seq-offset", cfg.HTTPS.FakeSeqOffset).
		Int64("ack-offset", cfg.HTTPS.FakeAckOffset).
		Bool("bad-md5sig", cfg.HTTPS.FakeBadMD5Sig).
		Str("syn-ack-timeout", fmt.Sprintf("%dms", cfg.HTTPS.SynAckTimeout.Milliseconds())).
		Msg(" fake")

	if cfg.DNS.Timeout > 0 {
		logger.Info().
			Str("value", fmt.Sprintf("%dms", cfg.DNS.Timeout.Milliseconds())).
			Msgf("dns connection timeout")
	}
	if cfg.Conn.TCPTimeout > 0 {
		logger.Info().
			Str("value", fmt.Sprintf("%dms", cfg.Conn.TCPTimeout.Milliseconds())).
			Msgf("tcp connection timeout")
	}
	if cfg.Conn.UDPIdleTimeout > 0 {
		logger.Info().
			Str("value", fmt.Sprintf("%dms", cfg.Conn.UDPIdleTimeout.Milliseconds())).
			Msgf("udp idle timeout")
	}

	time.Sleep(300 * time.Millisecond)
	if err := srv.Listen(appctx); err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	// livetest waits for this message to know that spoofdpi is ready
	// (internal/livetest/case.go).
	logger.Info().Msgf("server started on %s", srv.Addr())
	serveCtx := appctx
	if cfg.App.AutoConfigureNetwork {
		if stateFile, acErr := srv.SetupNetworkJobs(appctx); acErr != nil {
			// Non-fatal: server is running, just couldn't auto-set
			// system proxy. Log and continue rather than tearing down.
			logger.Error().Err(acErr).Msg("failed to set system network config")
		} else if acErr := server.ApplyJobs(logger, stateFile); acErr != nil {
			logger.Error().Err(acErr).Msg("failed to apply network config")
		} else {
			// Restore the network config as soon as shutdown starts, and
			// only then shut the server down: closing a TUN device removes
			// its routes, which would make their reset commands fail.
			var restore func()
			serveCtx, restore = shutdownAfter(appctx, func() {
				server.ResetJobs(logger, stateFile)
			})
			defer restore()
		}
	}

	sw.SetWriter(writer)

	return srv.Serve(serveCtx)
}

// shutdownAfterLimit bounds how long shutdownAfter holds the server up while
// fn runs, so a hung reset command cannot keep the server from stopping.
const shutdownAfterLimit = 5 * time.Second

// shutdownAfter returns a context for the server that ends once ctx is done
// and fn has returned, or shutdownAfterLimit after ctx is done, so fn runs
// while the server is still up. It keeps ctx's values. The returned func runs
// fn now if it has not run yet, and ends the context.
func shutdownAfter(ctx context.Context, fn func()) (context.Context, func()) {
	serveCtx, stop := context.WithCancel(context.WithoutCancel(ctx))
	runNow := runOnceWhenDone(ctx, func() {
		limit := time.AfterFunc(shutdownAfterLimit, stop)
		defer limit.Stop()
		defer stop()
		fn()
	})
	return serveCtx, func() {
		defer stop()
		runNow()
	}
}

// runOnceWhenDone runs fn once, as soon as ctx is done, and returns a func
// that runs fn now if it has not run yet. A call of the returned func while
// fn is running waits for fn to return.
func runOnceWhenDone(ctx context.Context, fn func()) func() {
	once := sync.OnceFunc(fn)
	stop := context.AfterFunc(ctx, once)

	return func() {
		stop()
		once()
	}
}

func setupNetworkStack(
	ctx context.Context,
	logger zerolog.Logger,
	route *netutil.Route,
	cfg *config.Config,
) (
	tcpStack *packet.TCPStack,
	udpStack *packet.UDPStack,
	hops *packet.HopStore,
	err error,
) {
	if !cfg.NeedsNetworkStack() {
		return
	}

	pktLogger := logging.WithScope(logger, "pkt")
	hops = packet.NewHopStore()

	logger.Info().Msg("network info")
	logger.Info().
		Str("name", route.Iface.Name).
		Str("mac", route.Iface.HardwareAddr.String()).
		Msg(" interface")

	sender, sErr := packet.OpenIPv4Sender(
		ctx,
		logger,
		route,
		fakeSenderOptions(cfg, route),
	)
	if sErr != nil {
		err = fakeSenderError(sErr)
		return
	}
	senders := packet.Senders{V4: sender}

	if cfg.NeedsTCPStack() {
		stack, hErr := packet.OpenTCPStack(
			pktLogger,
			&route.Iface,
			senders,
			hops,
		)
		if hErr != nil {
			_ = sender.Close()
			err = fmt.Errorf("tcp pcap handle on %s: %w", route.Iface.Name, hErr)
			return
		}
		tcpStack = stack
	}

	if cfg.NeedsUDPStack() {
		stack, hErr := packet.OpenUDPStack(
			pktLogger,
			&route.Iface,
			senders,
			hops,
		)
		if hErr != nil {
			_ = sender.Close()
			err = fmt.Errorf("udp pcap handle on %s: %w", route.Iface.Name, hErr)
			return
		}
		udpStack = stack
	}

	return
}

// fakeSenderOptions returns the options of the raw sockets that fake
// packets leave through. In TUN mode they are pinned to the physical
// interface like the dialed connections, so that the TUN's routes cannot
// carry the fakes into the TUN. The proxy modes leave the route to the
// kernel.
func fakeSenderOptions(cfg *config.Config, route *netutil.Route) inject.Options {
	if cfg.App.Mode != config.AppModeTUN {
		return inject.Options{}
	}
	return inject.Options{Control: tun.EgressControl(route, cfg.App.FreebsdFIB)}
}

// fakeSenderError explains err, a failure to open the sender of fake
// packets, with what the user can do about missing privileges.
func fakeSenderError(err error) error {
	if errors.Is(err, inject.ErrNeedsRoot) {
		return fmt.Errorf(
			"fake packet sender: %w; run as root, or set tls.fake-preflight, "+
				"tls.fake-stutter and udp.fake-preflight to 0, globally and in "+
				"every [[rules]] entry that sets them",
			err,
		)
	}
	return fmt.Errorf("fake packet sender: %w", err)
}

// noIPv4RouteError explains err, a failed IPv4 default route discovery,
// and what the user can do about it. hasIPv6 tells whether the host has an
// IPv6 route to the internet.
func noIPv4RouteError(err error, hasIPv6 bool) error {
	ipv6Route := "absent"
	if hasIPv6 {
		ipv6Route = "present"
	}
	return fmt.Errorf(
		"fake packets and TUN mode need an IPv4 default route; none found "+
			"(IPv6 route: %s). IPv6-only networks are not supported yet; disable "+
			"fake packets, use HTTP/SOCKS5 mode, or set --gateway: %w",
		ipv6Route,
		err,
	)
}

// logTUNNotes logs how TUN mode treats the IPv6 and DNS settings of cfg.
// hasIPv6Egress tells whether the host has an IPv6 route to the internet.
func logTUNNotes(logger zerolog.Logger, cfg *config.Config, hasIPv6Egress bool) {
	if !cfg.IPv6Enabled() && hasIPv6Egress {
		logger.Warn().Msg(
			"IPv6 traffic bypasses spoofdpi in TUN mode; " +
				"enable --ipv6 or disable IPv6 on the system",
		)
	}
	if tunIgnoresSettings(cfg) {
		logger.Info().Msg("the rules' ipv6 and the dns settings are ignored in TUN mode")
	}
}

// tunIgnoresSettings reports whether cfg has settings that the proxy modes
// apply and TUN mode ignores, as the OS and the applications resolve names
// and choose the address family there: a rule that sets its own ipv6, or
// DNS settings other than the defaults.
func tunIgnoresSettings(cfg *config.Config) bool {
	defaultDNS := config.DefaultConfig().DNS
	if !sameDNSSettings(cfg.DNS, defaultDNS) {
		return true
	}
	for _, r := range cfg.Rules {
		if r.IPv6 != nil || !sameDNSSettings(r.Config.DNS, defaultDNS) {
			return true
		}
	}
	return false
}

// sameDNSSettings reports whether a and b have the same DNS settings.
// QType is not one of them: it follows the ipv6 option.
func sameDNSSettings(a, b config.DNSOptions) bool {
	return a.Mode == b.Mode &&
		a.Addr.String() == b.Addr.String() &&
		a.HTTPSURL == b.HTTPSURL &&
		a.Timeout == b.Timeout
}

func createServer(
	appctx context.Context,
	logger zerolog.Logger,
	cfg *config.Config,
) (server.Server, error) {
	// --- Rule set ---
	ruleSet := rule.NewRuleSet()
	for _, r := range cfg.Rules {
		if err := ruleSet.Add(&r); err != nil {
			return nil, err
		}
	}

	// --- DNS resolver ---
	resolver := dns.NewClient(
		logging.WithScope(logger, "dns"),
		&cfg.DNS,
	)

	// Clean up stale network state before route discovery so a crashed TUN
	// session does not leave the routing table in a state that obscures the
	// real default route.
	server.ResetJobs(logger, tun.StateFile)
	server.ResetJobs(logger, http.StateFile)
	server.ResetJobs(logger, socks5.StateFile)

	var defaultRoute *netutil.Route
	if cfg.NeedsRoute() {
		var err error
		defaultRoute, err = netutil.DiscoverRoute(cfg.App.Gateway.V4)
		if errors.Is(err, netutil.ErrNoIPv4Route) {
			_, hasIPv6 := netutil.IPv6Egress()
			return nil, noIPv4RouteError(err, hasIPv6)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to find default route: %w", err)
		}
	} else if cfg.App.Gateway.V4 != nil {
		logger.Warn().
			Str("gateway", cfg.App.Gateway.V4.String()).
			Msg("gateway is ignored; only fake packets and tun mode use it")
	}

	tcpStack, udpStack, hops, err := setupNetworkStack(
		appctx,
		logger,
		defaultRoute,
		cfg,
	)
	if err != nil {
		return nil, err
	}

	// A nil stack must leave the interfaces nil: a nil *HopStore stored in
	// a packet.HopReader would be non-nil and defeat the desyncers' nil
	// checks.
	var (
		tcpHops   packet.HopReader
		tcpWriter packet.TCPSeqWriter
		seqs      *packet.SeqTracker
		tcpCaps   packet.FakeCapability
		udpHops   packet.HopReader
		udpWriter packet.Writer
		udpCaps   packet.FakeCapability
	)
	fakeGate := packet.NewStaticGate(
		nil,
		&packet.FakesOffError{
			Family: netutil.FamilyV6,
			Reason: "IPv6 fakes are not supported yet",
		},
	)
	if tcpStack != nil {
		tcpHops, tcpWriter, seqs = hops, tcpStack.Writer, tcpStack.Seqs
		tcpCaps = fakeGate
	}
	if udpStack != nil {
		udpHops, udpWriter = hops, udpStack.Writer
		udpCaps = fakeGate
	}

	tlsDesyncer := desync.NewTLSDesyncer(
		logging.WithScope(logger, "dsn"),
		tcpWriter,
		tcpHops,
		seqs,
		tcpCaps,
	)
	udpDesyncer := desync.NewUDPDesyncer(
		logging.WithScope(logger, "dsn"),
		udpWriter,
		udpHops,
		udpCaps,
	)

	switch cfg.App.Mode {
	case config.AppModeHTTP:
		return http.NewHTTPProxy(
			logging.WithScope(logger, "srv"),
			http.NewHTTPHandler(
				logging.WithScope(logger, "hnd"),
				resolver,
				ruleSet,
				cfg.App.ListenAddr,
				&cfg.RuntimeConfig,
			),
			http.NewHTTPSHandler(
				logging.WithScope(logger, "hnd"),
				tlsDesyncer,
				resolver,
				ruleSet,
				cfg.App.ListenAddr,
				&cfg.RuntimeConfig,
			),
			cfg.App.ListenAddr,
		), nil

	case config.AppModeSOCKS5:
		return socks5.NewSOCKS5Proxy(
			logging.WithScope(logger, "srv"),
			socks5.NewConnectHandler(
				logging.WithScope(logger, "hnd"),
				tlsDesyncer,
				resolver,
				ruleSet,
				cfg.App.ListenAddr,
				&cfg.RuntimeConfig,
			),
			socks5.NewBindHandler(logging.WithScope(logger, "hnd")),
			socks5.NewUdpAssociateHandler(
				logging.WithScope(logger, "hnd"),
				udpDesyncer,
				resolver,
				ruleSet,
				&cfg.RuntimeConfig,
			),
			cfg.App.ListenAddr,
		), nil

	case config.AppModeTUN:
		logger.Info().
			Str("interface", defaultRoute.Iface.Name).
			Str("gateway", defaultRoute.Gateway.String()).
			Msg("determined default interface and gateway")
		_, hasIPv6Egress := netutil.IPv6Egress()
		logTUNNotes(logger, cfg, hasIPv6Egress)
		sysNet, err := tun.NewTUNSystemNetwork(
			logging.WithScope(logger, "sys"),
			defaultRoute,
			cfg.App.FreebsdFIB,
			cfg.IPv6Enabled(),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create sysnet: %w", err)
		}
		return tun.NewTUNServer(
			logging.WithScope(logger, "srv"),
			tun.NewTCPHandler(
				logging.WithScope(logger, "hnd"),
				tlsDesyncer,
				ruleSet,
				&cfg.RuntimeConfig,
			),
			tun.NewUDPHandler(
				logging.WithScope(logger, "hnd"),
				udpDesyncer,
				ruleSet,
				&cfg.RuntimeConfig,
			),
			sysNet,
		), nil

	default:
		return nil, fmt.Errorf("unknown server mode: %s", cfg.App.Mode)
	}
}
