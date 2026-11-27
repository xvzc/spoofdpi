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
	"sync/atomic"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/desync"
	"github.com/xvzc/spoofdpi/internal/dns"
	"github.com/xvzc/spoofdpi/internal/logging"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/packetio/inject"
	"github.com/xvzc/spoofdpi/internal/route"
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

// SwitchableWriter writes to a target that can be switched while other
// goroutines write. SetWriter must be called before the first Write.
type SwitchableWriter struct {
	target atomic.Pointer[io.Writer]
}

func (sw *SwitchableWriter) SetWriter(w io.Writer) {
	sw.target.Store(&w)
}

func (sw *SwitchableWriter) Write(p []byte) (n int, err error) {
	return (*sw.target.Load()).Write(p)
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
	sw := &SwitchableWriter{}
	sw.SetWriter(dw)

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
	// livetest reads this message, and the dir field, to report the config
	// file its baseline case loaded (internal/livetest/case.go). When no file
	// is found, config.Load adds a warning to config.WarnMsgs instead.
	if configDir != "" {
		logger.Info().
			Str("dir", configDir).
			Msgf("loaded config file")
	}

	for _, m := range config.WarnMsgs {
		logger.Warn().Msg(m)
	}

	logger.Info().Str("mode", cfg.App.Mode.String()).Msgf("app")

	// Clean up what a run that crashed left behind before createServer
	// discovers the routes, so its routes do not obscure the real default
	// route, and before the TUN's table and rule prefs are chosen. Only what
	// spoofdpi tagged is removed; anything else is left with a warning.
	server.WarnLegacyStateFiles(logger)
	tun.CleanLeftovers(logger, tun.CleanupOptions{FreeBSDFIB: cfg.App.FreebsdFIB})
	server.CleanSystemProxyLeftovers(logger)

	srv, err := createServer(appctx, logger, cfg)
	if err != nil {
		return fmt.Errorf("create server: %w", err)
	}
	showActiveConns(srv.ActiveConns)

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
	// shutdownCtx ends once the start of shutdown is logged, so the log
	// comes before the ones of restoring the network and stopping the server.
	// Shutdown begins on a signal, or when the server stops on its own.
	shutdownCtx, endShutdownCtx := context.WithCancel(context.WithoutCancel(appctx))
	beginShutdown := sync.OnceFunc(func() {
		logger.Info().Msg("shutting down")
		endShutdownCtx()
	})
	context.AfterFunc(appctx, beginShutdown)
	serveCtx := shutdownCtx
	if cfg.App.AutoConfigureNetwork {
		var applied []server.NetworkJob
		jobs, acErr := srv.SetupNetworkJobs(appctx)
		if acErr != nil {
			acErr = fmt.Errorf("set system network config: %w", acErr)
		} else if applied, acErr = server.ApplyJobs(logger, jobs); acErr != nil {
			acErr = fmt.Errorf("apply network config: %w", acErr)
		}
		switch {
		case acErr == nil:
			// Restore the network config as soon as shutdown starts, and
			// only then shut the server down: closing a TUN device removes
			// its routes, which would make their reset commands fail.
			var restore func()
			serveCtx, restore = shutdownAfter(shutdownCtx, func() {
				server.ResetJobs(logger, applied)
				checkLeftoversAfterReset(logger, cfg.App.Mode)
			})
			defer restore()
		case isNetworkSetupFatal(cfg.App.Mode):
			// ApplyJobs rolled back its own jobs, so there is nothing to
			// reset. Serve on an ended context only closes the server.
			beginShutdown()
			if sErr := srv.Serve(shutdownCtx); sErr != nil {
				logger.Error().Err(sErr).Msg("failed to stop server")
			}
			return acErr
		default:
			// Non-fatal: server is running, just couldn't auto-set
			// system proxy. Log and continue rather than tearing down.
			logger.Error().Err(acErr).Msg("failed to configure system network")
		}
	}

	sw.SetWriter(writer)

	// Deferred last, so it runs first: before the network is restored.
	defer beginShutdown()
	return srv.Serve(serveCtx)
}

// isNetworkSetupFatal reports whether a failure to set up the network config
// must end the run. The TUN server has no traffic without its routes, while
// the HTTP and SOCKS5 proxies still work when only the system proxy fails.
func isNetworkSetupFatal(mode config.AppModeType) bool {
	return mode == config.AppModeTUN
}

// checkLeftoversAfterReset warns about the network configuration of this run
// in mode that ResetJobs left in place.
func checkLeftoversAfterReset(logger zerolog.Logger, mode config.AppModeType) {
	if mode == config.AppModeTUN {
		tun.CheckLeftoversAfterReset(logger)
		return
	}
	server.CheckSystemProxyLeftoversAfterReset(logger)
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

// stackOpeners open what setupNetworkStack sets up. Tests replace them to
// fake the host.
type stackOpeners struct {
	sender openSenderFunc
	tcp    func(
		runID string,
		logger zerolog.Logger,
		ifaces []desync.EgressIface,
		senders desync.Senders,
		hops *desync.HopStore,
	) (*desync.TCPStack, error)
	udp func(
		runID string,
		logger zerolog.Logger,
		ifaces []desync.EgressIface,
		senders desync.Senders,
		hops *desync.HopStore,
	) (*desync.UDPStack, error)
}

var osStackOpeners = stackOpeners{
	sender: desync.OpenSender,
	tcp:    desync.OpenTCPStack,
	udp:    desync.OpenUDPStack,
}

// setupNetworkStack opens, with open, the senders and the stacks of the
// fake packets that cfg sends, if it sends any. fakesV6 says why fake
// packets are off for IPv6, or is nil when they are sent to IPv6 servers;
// it is meaningful only when a stack is returned.
func setupNetworkStack(
	ctx context.Context,
	logger zerolog.Logger,
	startup startupNet,
	cfg *config.Config,
	open stackOpeners,
) (
	tcpStack *desync.TCPStack,
	udpStack *desync.UDPStack,
	hops *desync.HopStore,
	fakesV6 error,
	err error,
) {
	if !cfg.NeedsNetworkStack() {
		return
	}

	runID, _ := logging.TraceIDFromContext(ctx)
	hops = desync.NewHopStore()

	senders, fakesV6, err := openFakeSenders(logger, cfg, startup, open.sender)
	if err != nil {
		return
	}
	closeSenders := func() {
		_ = senders.V4.Close()
		if senders.V6 != nil {
			_ = senders.V6.Close()
		}
	}
	ifaces := egressIfaces(startup, senders)

	logger.Info().Msg("network info")
	for _, e := range ifaces {
		logger.Info().
			Str("name", e.Iface.Name).
			Strs("families", familyNames(e.Fams)).
			Msg(" interface")
	}

	if cfg.NeedsTCPStack() {
		stack, hErr := open.tcp(
			runID,
			logger,
			ifaces,
			senders,
			hops,
		)
		if hErr != nil {
			closeSenders()
			err = fmt.Errorf("tcp pcap handle %w", hErr)
			return
		}
		tcpStack = stack
	}

	if cfg.NeedsUDPStack() {
		stack, hErr := open.udp(
			runID,
			logger,
			ifaces,
			senders,
			hops,
		)
		if hErr != nil {
			closeSenders()
			err = fmt.Errorf("udp pcap handle %w", hErr)
			return
		}
		udpStack = stack
	}

	return
}

// egressIfaces returns the interfaces that the packets of the network
// stack are captured on: the one of each egress in startup whose fake
// packets senders can send, with the families that leave through it.
// Both families share an entry when they leave through the same
// interface, so that it gets one capture handle.
func egressIfaces(startup startupNet, senders desync.Senders) []desync.EgressIface {
	var ifaces []desync.EgressIface
	add := func(egress *route.Egress, fam netutil.Family) {
		if egress == nil {
			return
		}
		for i := range ifaces {
			if ifaces[i].Iface.Index == egress.Route.Iface.Index {
				ifaces[i].Fams |= netutil.NewFamilySet(fam)
				return
			}
		}
		ifaces = append(ifaces, desync.EgressIface{
			Iface: egress.Route.Iface,
			Fams:  netutil.NewFamilySet(fam),
		})
	}
	add(startup.V4, netutil.FamilyV4)
	if senders.V6 != nil {
		add(startup.V6, netutil.FamilyV6)
	}
	return ifaces
}

// familyNames returns the names of the families in fams, for logs.
func familyNames(fams netutil.FamilySet) []string {
	var names []string
	for _, fam := range []netutil.Family{netutil.FamilyV4, netutil.FamilyV6} {
		if fams.Has(fam) {
			names = append(names, fam.String())
		}
	}
	return names
}

// openSenderFunc opens the sender of the fake packets of fam, as
// desync.OpenSender does.
type openSenderFunc func(fam netutil.Family, opts inject.Options) (inject.Sender, error)

// openFakeSenders opens, with open, the senders of the fake packets of
// the families that startup has an egress for, and returns why fake
// packets are off for IPv6, as fakesOffV6 does. It fails if the IPv4
// sender does not open. The IPv6 sender is opened outside TUN mode only,
// as TUN mode does not carry IPv6 traffic; when it does not open, a
// warning is logged and IPv6 has no sender.
func openFakeSenders(
	logger zerolog.Logger,
	cfg *config.Config,
	startup startupNet,
	open openSenderFunc,
) (senders desync.Senders, fakesV6 error, err error) {
	v4, err := open(netutil.FamilyV4, fakeSenderOptions(logger, cfg, &startup.V4.Route))
	if err != nil {
		return desync.Senders{}, nil, fakeSenderError(err)
	}
	senders = desync.Senders{V4: v4}
	if startup.V6 == nil || cfg.App.Mode == config.AppModeTUN {
		return senders, fakesOffV6(cfg, startup, nil), nil
	}

	v6, err := open(netutil.FamilyV6, fakeSenderOptions(logger, cfg, &startup.V6.Route))
	if err != nil {
		logger.Warn().
			Err(err).
			Msg("failed to open the IPv6 fake packet sender; " +
				"fake packets are off for IPv6")
		return senders, fakesOffV6(cfg, startup, err), nil
	}
	senders.V6 = v6
	return senders, nil, nil
}

// fakesOffV6 returns why fake packets are off for IPv6, or nil when they
// are sent to IPv6 servers: when startup has an IPv6 egress, the mode is
// not TUN, and the IPv6 sender opened. senderErr is why the IPv6 sender
// did not open, or nil.
func fakesOffV6(cfg *config.Config, startup startupNet, senderErr error) error {
	off := func(kind, reason string) error {
		return &desync.FakesOffError{Family: netutil.FamilyV6, Kind: kind, Reason: reason}
	}
	switch {
	case startup.V6 == nil && startup.IPv6Off == ipv6OffNoRoute:
		return off(desync.FakesOffIPv6Disabled, "no usable IPv6 route was found")
	case startup.V6 == nil:
		return off(desync.FakesOffIPv6Disabled, "IPv6 is not enabled")
	case cfg.App.Mode == config.AppModeTUN:
		return off(
			desync.FakesOffIPv6Unsupported,
			"IPv6 fakes are not supported in TUN mode yet",
		)
	case senderErr != nil:
		return off(
			desync.FakesOffIPv6NoSender,
			"the IPv6 sender did not open: "+senderErr.Error(),
		)
	default:
		return nil
	}
}

// fakeSenderOptions returns the options of the raw sockets of rt's family
// that fake packets leave through. In TUN mode they are pinned to rt, the
// egress of that family, like the dialed connections, so that the TUN's
// routes cannot carry the fakes into the TUN. The proxy modes leave the
// route to the kernel. What fails without failing the open is logged to
// logger.
func fakeSenderOptions(
	logger zerolog.Logger,
	cfg *config.Config,
	rt *route.Route,
) inject.Options {
	if cfg.App.Mode != config.AppModeTUN {
		return inject.Options{Logger: logger}
	}
	return inject.Options{
		Control: tun.EgressControl(rt, cfg.App.FreebsdFIB),
		Logger:  logger,
	}
}

// fakesPinning describes where fakeSenderOptions pins fake packets on goos,
// for the startup log: an interface name, "fib N" on FreeBSD, or "none"
// when the kernel routes them.
func fakesPinning(goos string, cfg *config.Config, rt *route.Route) string {
	if cfg.App.Mode != config.AppModeTUN || rt == nil {
		return "none"
	}
	if goos == "freebsd" {
		return fmt.Sprintf("fib %d", cfg.App.FreebsdFIB)
	}
	return rt.Iface.Name
}

// fakesState describes fakesOff, the reason fake packets are off for a
// family, for the startup log: "on" when it is nil.
func fakesState(fakesOff error) string {
	if fakesOff == nil {
		return "on"
	}
	var off *desync.FakesOffError
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
			"fake packets and use HTTP or SOCKS5 mode: %w",
		ipv6Route,
		err,
	)
}

// logTUNNotes logs how TUN mode treats the IPv6 and DNS settings of cfg.
// hasIPv6Egress tells whether the host has an IPv6 route to the internet,
// and ipv6Off why IPv6 was turned off at startup, if it was. IPv6 traffic
// bypasses spoofdpi in TUN mode whenever IPv6 is off and the host has an
// IPv6 route.
func logTUNNotes(
	logger zerolog.Logger,
	cfg *config.Config,
	hasIPv6Egress bool,
	ipv6Off ipv6OffCause,
) {
	switch {
	case cfg.IPv6Enabled():
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
	// Egress discovery may turn IPv6 off in cfg, so it runs before anything
	// reads the ipv6 option or the DNS record types.
	startup, err := discoverEgresses(logger, cfg, osRouteFinder)
	if err != nil {
		return nil, err
	}
	var defaultRoute, egress6 *route.Route
	if startup.V4 != nil {
		defaultRoute = &startup.V4.Route
	}
	if startup.V6 != nil {
		egress6 = &startup.V6.Route
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
		tcpStack *desync.TCPStack
		udpStack *desync.UDPStack
		hops     *desync.HopStore
		fakesV6  error
	)
	tcpStack, udpStack, hops, fakesV6, err = setupNetworkStack(
		appctx,
		logger,
		startup,
		cfg,
		osStackOpeners,
	)
	if err != nil {
		return nil, err
	}
	if cfg.NeedsNetworkStack() {
		logger.Info().
			Str("v4", "on").
			Str("v6", fakesState(fakesV6)).
			Str("pinned", fakesPinning(runtime.GOOS, cfg, defaultRoute)).
			Msg("fake packets")
	}

	// A nil stack must leave the interfaces nil: a nil *HopStore stored in
	// a desync.HopReader would be non-nil and defeat the desyncers' nil
	// checks.
	var (
		tcpHops   desync.HopReader
		tcpWriter desync.TCPSeqWriter
		seqs      desync.SeqSource
		tcpCaps   desync.FakeCapability
		udpHops   desync.HopReader
		udpWriter desync.Writer
		udpCaps   desync.FakeCapability
	)
	fakeGate := desync.NewStaticGate(nil, fakesV6)
	if tcpStack != nil {
		tcpHops, tcpWriter, seqs = hops, tcpStack.Writer, tcpStack
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
	tlsAlerts := server.NewTLSAlertWatcher()
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
				tlsAlerts,
				resolver,
				ruleSet,
				cfg.App.ListenAddr,
				&cfg.RuntimeConfig,
			),
			cfg.App.ListenAddr,
			cfg.Conn.TCPTimeout,
		), nil

	case config.AppModeSOCKS5:
		return socks5.NewSOCKS5Proxy(
			logger,
			socks5.NewConnectHandler(
				logger,
				tlsDesyncer,
				tlsAlerts,
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
			cfg.Conn.TCPTimeout,
		), nil

	case config.AppModeTUN:
		logTUNNotes(logger, cfg, osRouteFinder.hasIPv6Egress(), startup.IPv6Off)
		// startup.V6 is there only when IPv6 is enabled and has an egress.
		sysNet, err := tun.NewTUNSystemNetwork(
			logger,
			defaultRoute,
			egress6,
			cfg.App.FreebsdFIB,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create sysnet: %w", err)
		}
		return tun.NewTUNServer(
			logger,
			tun.NewTCPHandler(
				logger,
				tlsDesyncer,
				tlsAlerts,
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
