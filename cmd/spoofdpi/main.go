package main

import (
	"context"
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
	cmd := config.CreateCommand(runApp, version, commit, build)
	if err := cmd.Run(context.Background(), os.Args); err != nil {
		fmt.Println("application failed to start")
		fmt.Fprintln(os.Stderr, err)
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
	if !cfg.Startup.App.NoTUI {
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

	logging.SetGlobalLogger(appctx, cfg.Startup.App.LogLevel, sw)
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
		if err == nil || cfg.Startup.App.NoTUI {
			return
		}
		logger.Error().Err(err).Msg("application failed to start")
		<-appctx.Done()
		err = nil
	}()

	logger.Info().Str("version", version).Msg("spoofdpi")
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

	logger.Info().Str("mode", cfg.Startup.App.Mode.String()).Msgf("app")

	srv, err := createServer(appctx, logger, cfg)
	if err != nil {
		return fmt.Errorf("create server: %w", err)
	}

	logger.Info().Msg("https info")
	logger.Info().
		Str("split-mode", cfg.Runtime.HTTPS.SplitMode.String()).
		Uint8("chunk-size", uint8(cfg.Runtime.HTTPS.ChunkSize)).
		Bool("disorder", cfg.Runtime.HTTPS.Disorder).
		Msg(" split")

	logger.Info().
		Uint8("count", uint8(cfg.Runtime.HTTPS.FakeCount)).
		Msg(" fake")

	if cfg.Runtime.Conn.DNSTimeout > 0 {
		logger.Info().
			Str("value", fmt.Sprintf("%dms", cfg.Runtime.Conn.DNSTimeout.Milliseconds())).
			Msgf("dns connection timeout")
	}
	if cfg.Runtime.Conn.TCPTimeout > 0 {
		logger.Info().
			Str("value", fmt.Sprintf("%dms", cfg.Runtime.Conn.TCPTimeout.Milliseconds())).
			Msgf("tcp connection timeout")
	}
	if cfg.Runtime.Conn.UDPIdleTimeout > 0 {
		logger.Info().
			Str("value", fmt.Sprintf("%dms", cfg.Runtime.Conn.UDPIdleTimeout.Milliseconds())).
			Msgf("udp idle timeout")
	}

	time.Sleep(300 * time.Millisecond)
	if err := srv.ListenAndServe(appctx); err != nil {
		return fmt.Errorf("listen and serve: %w", err)
	}
	logger.Info().Msgf("server started on %s", srv.Addr())
	if cfg.Startup.App.AutoConfigureNetwork {
		unset, acErr := srv.AutoConfigureNetwork(appctx)
		if acErr != nil {
			// Non-fatal: server is running, just couldn't auto-set
			// system proxy. Log and continue rather than tearing down.
			logger.Error().Err(acErr).Msg("failed to set system network config")
		} else if unset != nil {
			defer unset()
		}
	}

	sw.SetWriter(writer)

	<-appctx.Done()

	return nil
}

// setupPcapIO resolves the gateway MAC (populating route.GatewayMAC) and
// creates sniffer/writer pairs for whichever L4 protocols cfg requires.
// Returns nil values for protocols that don't need pcap.
func setupPcapIO(
	ctx context.Context,
	logger zerolog.Logger,
	route *netutil.Route,
	cfg *config.Config,
) (tcpSniffer, udpSniffer packet.Sniffer, tcpWriter, udpWriter packet.Writer, err error) {
	arpCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	mac, err := packet.ResolveGatewayMAC(
		arpCtx,
		logging.WithScope(logger, "pkt"),
		&route.Iface,
	)
	cancel()
	if err != nil {
		err = fmt.Errorf("failed to resolve gateway MAC: %w", err)
		return
	}
	route.GatewayMAC = mac

	pktLogger := logging.WithScope(logger, "pkt")
	hopCache := cache.NewLRUCache[netutil.IPKey, uint8](4096, nil)

	logger.Info().Msg("network info")
	logger.Info().
		Str("name", route.Iface.Name).
		Str("mac", route.Iface.HardwareAddr.String()).
		Msg(" interface")
	logger.Info().Str("mac", mac.String()).Msg(" gateway (passive detection)")

	if cfg.NeedsPcapTCP() {
		handle, hErr := packet.NewHandle(&route.Iface)
		if hErr != nil {
			err = fmt.Errorf("tcp pcap handle on %s: %w", route.Iface.Name, hErr)
			return
		}
		tcpSniffer = packet.NewTCPSniffer(
			pktLogger,
			hopCache,
			handle,
			uint8(cfg.Runtime.Conn.DefaultFakeTTL),
		)
		tcpWriter = packet.NewTCPWriter(pktLogger, handle, &route.Iface, mac)
	}

	if cfg.NeedsPcapUDP() {
		handle, hErr := packet.NewHandle(&route.Iface)
		if hErr != nil {
			err = fmt.Errorf("udp pcap handle on %s: %w", route.Iface.Name, hErr)
			return
		}
		udpSniffer = packet.NewUDPSniffer(
			pktLogger,
			hopCache,
			handle,
			uint8(cfg.Runtime.Conn.DefaultFakeTTL),
		)
		udpWriter = packet.NewUDPWriter(pktLogger, handle, &route.Iface, mac)
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
	for _, r := range cfg.Startup.Rules {
		if err := ruleSet.Add(&r); err != nil {
			return nil, err
		}
	}

	// --- DNS resolver ---
	resolver := dns.NewClient(
		logging.WithScope(logger, "dns"),
		&cfg.Runtime,
	)

	// Clean up stale network state before route discovery so a crashed TUN
	// session does not leave the routing table in a state that obscures the
	// real default route.
	tun.CleanupStaleState(logger)
	http.CleanupStaleState(logger)
	socks5.CleanupStaleState(logger)

	defaultRoute, err := netutil.DiscoverDefaultRoute()
	if err != nil {
		return nil, fmt.Errorf("failed to find default route: %w", err)
	}

	var tcpSniffer, udpSniffer packet.Sniffer
	var tcpWriter, udpWriter packet.Writer

	if cfg.NeedsPcap() {
		tcpSniffer, udpSniffer, tcpWriter, udpWriter, err = setupPcapIO(
			appctx,
			logger,
			defaultRoute,
			cfg,
		)
		if err != nil {
			return nil, err
		}
	}

	tlsDesyncer := desync.NewTLSDesyncer(
		logging.WithScope(logger, "dsn"),
		tcpWriter,
		tcpSniffer,
	)
	udpDesyncer := desync.NewUDPDesyncer(
		logging.WithScope(logger, "dsn"),
		udpWriter,
		udpSniffer,
	)

	switch cfg.Startup.App.Mode {
	case config.AppModeHTTP:
		return http.NewHTTPProxy(
			logging.WithScope(logger, "srv"),
			resolver,
			http.NewHTTPHandler(logging.WithScope(logger, "hnd")),
			http.NewHTTPSHandler(logging.WithScope(logger, "hnd"), tlsDesyncer, &cfg.Runtime),
			ruleSet,
			tcpSniffer,
			http.NewHTTPSystemNetwork(logging.WithScope(logger, "sys"), defaultRoute),
			cfg.Startup.App.ListenAddr,
			&cfg.Runtime,
		), nil

	case config.AppModeSOCKS5:
		udpPool := netutil.NewConnRegistry[netutil.NATKey](4096, 60*time.Second)
		udpPool.RunCleanupLoop(appctx)
		return socks5.NewSOCKS5Proxy(
			logging.WithScope(logger, "srv"),
			resolver,
			ruleSet,
			socks5.NewConnectHandler(
				logging.WithScope(logger, "hnd"),
				tlsDesyncer,
				cfg.Startup.App.ListenAddr,
				&cfg.Runtime,
			),
			socks5.NewBindHandler(logging.WithScope(logger, "hnd")),
			socks5.NewUdpAssociateHandler(
				logging.WithScope(logger, "hnd"),
				udpPool,
				udpDesyncer,
				&cfg.Runtime,
			),
			tcpSniffer,
			udpSniffer,
			socks5.NewSOCKS5SystemNetwork(logging.WithScope(logger, "sys"), defaultRoute),
			cfg.Startup.App.ListenAddr,
			&cfg.Runtime,
		), nil

	case config.AppModeTUN:
		logger.Info().
			Str("interface", defaultRoute.Iface.Name).
			Str("gateway", defaultRoute.Gateway.String()).
			Msg("determined default interface and gateway")
		sysNet, err := tun.NewTUNSystemNetwork(
			logging.WithScope(logger, "sys"),
			defaultRoute,
			cfg.Startup.App.FreebsdFIB,
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
				&cfg.Runtime,
			),
			tun.NewUDPHandler(
				logging.WithScope(logger, "hnd"),
				udpDesyncer,
				ruleSet,
				&cfg.Runtime,
			),
			tcpSniffer,
			udpSniffer,
			sysNet,
		), nil

	default:
		return nil, fmt.Errorf("unknown server mode: %s", cfg.Startup.App.Mode)
	}
}
