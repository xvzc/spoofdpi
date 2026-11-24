package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
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
	// The run ID is the trace ID of every log that belongs to no connection.
	// Connections start from their own root context, so they keep their own.
	appctx, cancel := signal.NotifyContext(
		logging.ContextWithTraceID(mainctx, logging.NewTraceID()),
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

	runID, _ := logging.TraceIDFromContext(ctx)
	hops = packet.NewHopStore()

	logger.Info().Msg("network info")
	logger.Info().
		Str("name", route.Iface.Name).
		Msg(" interface")

	sender, sErr := packet.OpenIPv4Sender(
		ctx,
		logger,
		fakeSenderOptions(cfg, route),
	)
	if sErr != nil {
		err = fakeSenderError(sErr)
		return
	}
	senders := packet.Senders{V4: sender}

	if cfg.NeedsTCPStack() {
		stack, hErr := packet.OpenTCPStack(
			runID,
			logger,
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
			runID,
			logger,
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

// fakesPinning describes where fakeSenderOptions pins fake packets on goos,
// for the startup log: an interface name, "fib N" on FreeBSD, or "none"
// when the kernel routes them or fakesV4 turned them off.
func fakesPinning(
	goos string,
	cfg *config.Config,
	route *netutil.Route,
	fakesV4 error,
) string {
	if fakesV4 != nil || cfg.App.Mode != config.AppModeTUN || route == nil {
		return "none"
	}
	if goos == "freebsd" {
		return fmt.Sprintf("fib %d", cfg.App.FreebsdFIB)
	}
	return route.Iface.Name
}

// fakesState describes fakesOff, the reason fake packets are off for a
// family, for the startup log: "on" when it is nil.
func fakesState(fakesOff error) string {
	if fakesOff == nil {
		return "on"
	}
	var off *packet.FakesOffError
	if errors.As(fakesOff, &off) {
		return "off: " + off.Reason
	}
	return "off: " + fakesOff.Error()
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
			"fake packets, use HTTP or SOCKS5 mode, or set --gateway: %w",
		ipv6Route,
		err,
	)
}

// logTUNNotes logs how TUN mode treats the IPv6 and DNS settings of cfg.
// hasIPv6Egress tells whether the host has an IPv6 route to the internet,
// and ipv6Off why IPv6 was turned off at startup, if it was. IPv6 traffic
// bypasses spoofdpi in TUN mode whenever IPv6 is off and the host has an
// IPv6 route; a VPN that carries IPv6 is such a route by itself.
func logTUNNotes(
	logger zerolog.Logger,
	cfg *config.Config,
	hasIPv6Egress bool,
	ipv6Off ipv6OffCause,
) {
	switch {
	case cfg.IPv6Enabled():
	case ipv6Off == ipv6OffVPN:
		logger.Warn().Msg(
			"IPv6 was disabled because a full-tunnel VPN carries IPv6; " +
				"IPv6 traffic goes through the VPN and bypasses spoofdpi",
		)
	case !hasIPv6Egress:
	case ipv6Off == ipv6OffNoRoute:
		logger.Warn().Msg(
			"IPv6 was disabled because no usable IPv6 route was found; " +
				"IPv6 traffic bypasses spoofdpi in TUN mode; " +
				"disable IPv6 on the system to keep it from leaking",
		)
	default:
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
	// Clean up stale network state before route discovery so a crashed TUN
	// session does not leave the routing table in a state that obscures the
	// real default route.
	server.ResetJobs(logger, tun.StateFile)
	server.ResetJobs(logger, http.StateFile)
	server.ResetJobs(logger, socks5.StateFile)

	// Egress discovery may turn IPv6 off in cfg, so it runs before anything
	// reads the ipv6 option or the DNS record types.
	startup, err := discoverEgresses(logger, cfg, osRouteFinder)
	if err != nil {
		return nil, err
	}
	var defaultRoute *netutil.Route
	if startup.V4 != nil {
		defaultRoute = &startup.V4.Route
	}

	// --- Rule set ---
	ruleSet := rule.NewRuleSet()
	for _, r := range cfg.Rules {
		if err := ruleSet.Add(&r); err != nil {
			return nil, err
		}
	}

	// --- DNS resolver ---
	resolver := dns.NewClient(
		logger,
		&cfg.DNS,
	)

	var (
		tcpStack *packet.TCPStack
		udpStack *packet.UDPStack
		hops     *packet.HopStore
	)
	if startup.FakesV4 == nil {
		tcpStack, udpStack, hops, err = setupNetworkStack(
			appctx,
			logger,
			defaultRoute,
			cfg,
		)
		if err != nil {
			return nil, err
		}
	}
	if cfg.NeedsNetworkStack() {
		logger.Info().
			Str("v4", fakesState(startup.FakesV4)).
			Str("v6", fakesState(startup.FakesV6)).
			Str("pinned", fakesPinning(runtime.GOOS, cfg, defaultRoute, startup.FakesV4)).
			Msg("fake packets")
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
	staticGate := packet.NewStaticGate(startup.FakesV4, startup.FakesV6)
	var fakeGate packet.FakeCapability = staticGate
	// The proxy modes check each server's route too. TUN mode routes the
	// whole traffic itself, and a full-tunnel VPN stops it at startup.
	if (tcpStack != nil || udpStack != nil) && cfg.App.Mode != config.AppModeTUN {
		fakeGate = packet.NewRouteGate(
			staticGate,
			dstFakeCheck(
				logger,
				startup.V4,
				netutil.RouteTo,
				netutil.ClassifyPath,
			),
			packet.RouteGateOptions{},
		)
	}
	if tcpStack != nil {
		tcpHops, tcpWriter, seqs = hops, tcpStack.Writer, tcpStack.Seqs
		tcpCaps = fakeGate
	}
	if udpStack != nil {
		udpHops, udpWriter = hops, udpStack.Writer
		udpCaps = fakeGate
	}

	tlsDesyncer := desync.NewTLSDesyncer(
		logger,
		tcpWriter,
		tcpHops,
		seqs,
		tcpCaps,
	)
	udpDesyncer := desync.NewUDPDesyncer(
		logger,
		udpWriter,
		udpHops,
		udpCaps,
	)

	switch cfg.App.Mode {
	case config.AppModeHTTP:
		return http.NewHTTPProxy(
			logger,
			http.NewHTTPHandler(
				logger,
				resolver,
				ruleSet,
				cfg.App.ListenAddr,
				&cfg.RuntimeConfig,
			),
			http.NewHTTPSHandler(
				logger,
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
			logger,
			socks5.NewConnectHandler(
				logger,
				tlsDesyncer,
				resolver,
				ruleSet,
				cfg.App.ListenAddr,
				&cfg.RuntimeConfig,
			),
			socks5.NewBindHandler(logger),
			socks5.NewUdpAssociateHandler(
				logger,
				udpDesyncer,
				resolver,
				ruleSet,
				&cfg.RuntimeConfig,
			),
			cfg.App.ListenAddr,
		), nil

	case config.AppModeTUN:
		logTUNNotes(logger, cfg, osRouteFinder.hasIPv6Egress(), startup.IPv6Off)
		sysNet, err := tun.NewTUNSystemNetwork(
			logger,
			defaultRoute,
			cfg.App.FreebsdFIB,
			cfg.IPv6Enabled(),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create sysnet: %w", err)
		}
		return tun.NewTUNServer(
			logger,
			tun.NewTCPHandler(
				logger,
				tlsDesyncer,
				ruleSet,
				&cfg.RuntimeConfig,
			),
			tun.NewUDPHandler(
				logger,
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
