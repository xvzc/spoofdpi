package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/xvzc/spoofdpi/internal/cache"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/desync"
	"github.com/xvzc/spoofdpi/internal/dns"
	"github.com/xvzc/spoofdpi/internal/logging"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/packet"
	"github.com/xvzc/spoofdpi/internal/rule"
	"github.com/xvzc/spoofdpi/internal/server"
	"github.com/xvzc/spoofdpi/internal/server/http"
	"github.com/xvzc/spoofdpi/internal/server/socks5"
	"github.com/xvzc/spoofdpi/internal/server/tun"
	"github.com/xvzc/spoofdpi/internal/session"
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
		session.WithNewTraceID(mainctx),
		syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP,
	)
	defer cancel()

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
	if err := srv.ListenAndServe(appctx); err != nil {
		return fmt.Errorf("listen and serve: %w", err)
	}
	// livetest waits for this message to know that spoofdpi is ready
	// (internal/livetest/case.go).
	logger.Info().Msgf("server started on %s", srv.Addr())
	if cfg.App.AutoConfigureNetwork {
		if stateFile, acErr := srv.SetupNetworkJobs(appctx); acErr != nil {
			// Non-fatal: server is running, just couldn't auto-set
			// system proxy. Log and continue rather than tearing down.
			logger.Error().Err(acErr).Msg("failed to set system network config")
		} else if acErr := server.ApplyJobs(logger, stateFile); acErr != nil {
			logger.Error().Err(acErr).Msg("failed to apply network config")
		} else {
			defer server.ResetJobs(logger, stateFile)
		}
	}

	sw.SetWriter(writer)

	<-appctx.Done()

	return nil
}

func setupNetworkStack(
	ctx context.Context,
	logger zerolog.Logger,
	route *netutil.Route,
	cfg *config.Config,
) (
	tcpStack *packet.TCPStack,
	udpStack *packet.UDPStack,
	err error,
) {
	if !cfg.NeedsNetworkStack() {
		return
	}

	resolveCtx, resolveCancel := context.WithTimeout(ctx, 10*time.Second)
	gatewayMAC, rErr := packet.ResolveGatewayMAC(
		resolveCtx,
		&route.Iface,
		route.LocalIP,
		route.Gateway,
	)
	resolveCancel()
	if rErr != nil {
		err = rErr
		return
	}

	pktLogger := logging.WithScope(logger, "pkt")
	hopCache := cache.NewLRUCache[netutil.IPKey, packet.HopEntry](16, 8192, nil)

	logger.Info().Msg("network info")
	logger.Info().
		Str("name", route.Iface.Name).
		Str("mac", route.Iface.HardwareAddr.String()).
		Msg(" interface")
	logger.Info().
		Str("mac", gatewayMAC.String()).
		Msg(" gateway")

	if cfg.NeedsTCPStack() {
		stack, hErr := packet.OpenTCPStack(
			pktLogger,
			&route.Iface,
			gatewayMAC,
			hopCache,
		)
		if hErr != nil {
			err = fmt.Errorf("tcp pcap handle on %s: %w", route.Iface.Name, hErr)
			return
		}
		tcpStack = stack
	}

	if cfg.NeedsUDPStack() {
		stack, hErr := packet.OpenUDPStack(
			pktLogger,
			&route.Iface,
			gatewayMAC,
			hopCache,
		)
		if hErr != nil {
			err = fmt.Errorf("udp pcap handle on %s: %w", route.Iface.Name, hErr)
			return
		}
		udpStack = stack
	}

	return
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
		defaultRoute, err = netutil.DiscoverRoute(cfg.App.Gateway)
		if err != nil {
			return nil, fmt.Errorf("failed to find default route: %w", err)
		}
	} else if cfg.App.Gateway != nil {
		logger.Warn().
			Str("gateway", cfg.App.Gateway.String()).
			Msg("gateway is ignored; only fake packets and tun mode use it")
	}

	tcpStack, udpStack, err := setupNetworkStack(
		appctx,
		logger,
		defaultRoute,
		cfg,
	)
	if err != nil {
		return nil, err
	}

	// A nil stack must leave the interfaces nil: a nil *TCPSniffer stored in
	// a packet.Sniffer would be non-nil and defeat the desyncers' nil checks.
	var (
		tcpSniffer packet.Sniffer
		tcpWriter  packet.TCPSeqWriter
		seqs       *packet.SeqTracker
		udpSniffer packet.Sniffer
		udpWriter  packet.Writer
	)
	if tcpStack != nil {
		tcpSniffer, tcpWriter, seqs = tcpStack.Sniffer, tcpStack.Writer, tcpStack.Seqs
	}
	if udpStack != nil {
		udpSniffer, udpWriter = udpStack.Sniffer, udpStack.Writer
	}

	tlsDesyncer := desync.NewTLSDesyncer(
		logging.WithScope(logger, "dsn"),
		tcpWriter,
		tcpSniffer,
		seqs,
	)
	udpDesyncer := desync.NewUDPDesyncer(
		logging.WithScope(logger, "dsn"),
		udpWriter,
		udpSniffer,
	)

	switch cfg.App.Mode {
	case config.AppModeHTTP:
		return http.NewHTTPProxy(
			logging.WithScope(logger, "srv"),
			http.NewHTTPHandler(logging.WithScope(logger, "hnd")),
			http.NewHTTPSHandler(
				logging.WithScope(logger, "hnd"),
				tlsDesyncer,
				&cfg.RuntimeConfig,
			),
			resolver,
			ruleSet,
			cfg.App.ListenAddr,
			&cfg.RuntimeConfig,
		), nil

	case config.AppModeSOCKS5:
		udpPool := netutil.NewConnRegistry[socks5.UDPFlowKey](4096)
		udpPool.RunCleanupLoop(appctx)
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
				udpPool,
				udpDesyncer,
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
		sysNet, err := tun.NewTUNSystemNetwork(
			logging.WithScope(logger, "sys"),
			defaultRoute,
			cfg.App.FreebsdFIB,
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
