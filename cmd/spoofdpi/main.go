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
	resolver := dns.NewMuxResolver(
		logging.WithScope(logger, "dns"),
		cache.NewTTLCache[string](cache.TTLCacheAttrs{
			NumOfShards:     64,
			CleanupInterval: 3 * time.Minute,
		}),
		&cfg.Runtime,
	)

	defaultRoute, err := netutil.DiscoverDefaultRoute()
	if err != nil {
		return nil, fmt.Errorf("failed to find default route: %w", err)
	}

	// --- Raw packet IO (sniffer + writer) per L4, only when needed ---
	var tcpSniffer, udpSniffer packet.Sniffer
	var tcpWriter, udpWriter packet.Writer

	needTCP := cfg.NeedsRawTCP()
	needUDP := cfg.NeedsRawUDP()

	if needTCP || needUDP {
		// Resolve the upstream gateway MAC for raw L2 packet emission.
		arpCtx, cancel := context.WithTimeout(appctx, 10*time.Second)
		mac, err := packet.ResolveGatewayMAC(
			arpCtx,
			logging.WithScope(logger, "pkt"),
			&defaultRoute.Iface,
		)
		cancel()
		if err != nil {
			return nil, fmt.Errorf("failed to resolve gateway MAC: %w", err)
		}
		defaultRoute.GatewayMAC = mac

		iface := &defaultRoute.Iface

		logger.Info().Msg("network info")
		logger.Info().
			Str("name", iface.Name).
			Str("mac", iface.HardwareAddr.String()).
			Msg(" interface")
		logger.Info().Str("mac", mac.String()).Msg(" gateway (passive detection)")

		// Shared cache for both TCP and UDP raw-packet stacks.
		hopCache := cache.NewLRUCache[netutil.IPKey](4096, nil)

		if needTCP {
			handle, err := packet.NewHandle(iface)
			if err != nil {
				return nil, fmt.Errorf("tcp pcap handle on %s: %w", iface.Name, err)
			}
			tcpSniffer = packet.NewTCPSniffer(
				logging.WithScope(logger, "pkt"),
				hopCache,
				handle,
				uint8(cfg.Runtime.Conn.DefaultFakeTTL),
			)
			tcpWriter = packet.NewTCPWriter(
				logging.WithScope(logger, "pkt"),
				handle,
				iface,
				mac,
			)
		}

		if needUDP {
			handle, err := packet.NewHandle(iface)
			if err != nil {
				return nil, fmt.Errorf("udp pcap handle on %s: %w", iface.Name, err)
			}
			udpSniffer = packet.NewUDPSniffer(
				logging.WithScope(logger, "pkt"),
				hopCache,
				handle,
				uint8(cfg.Runtime.Conn.DefaultFakeTTL),
			)
			udpWriter = packet.NewUDPWriter(
				logging.WithScope(logger, "pkt"),
				handle,
				iface,
				mac,
			)
		}
	}

	switch cfg.Startup.App.Mode {
	case config.AppModeHTTP:
		httpHandler := http.NewHTTPHandler(logging.WithScope(logger, "hnd"))
		httpsHandler := http.NewHTTPSHandler(
			logging.WithScope(logger, "hnd"),
			desync.NewTLSDesyncer(tcpWriter, tcpSniffer),
			tcpSniffer,
			&cfg.Runtime,
		)

		sysNet := http.NewHTTPSystemNetwork(
			logging.WithScope(logger, "sys"),
			defaultRoute,
		)

		return http.NewHTTPProxy(
			logging.WithScope(logger, "srv"),
			resolver,
			httpHandler,
			httpsHandler,
			ruleSet,
			tcpSniffer,
			sysNet,
			cfg.Startup.App.ListenAddr,
			&cfg.Runtime,
		), nil
	case config.AppModeSOCKS5:
		connectHandler := socks5.NewConnectHandler(
			logging.WithScope(logger, "hnd"),
			desync.NewTLSDesyncer(tcpWriter, tcpSniffer),
			tcpSniffer,
			cfg.Startup.App.ListenAddr,
			&cfg.Runtime,
		)
		udpPool := netutil.NewConnRegistry[netutil.NATKey](4096, 60*time.Second)
		udpPool.RunCleanupLoop(appctx)
		udpAssociateHandler := socks5.NewUdpAssociateHandler(
			logging.WithScope(logger, "hnd"),
			udpPool,
			desync.NewUDPDesyncer(
				logging.WithScope(logger, "dsn"),
				udpWriter,
				udpSniffer,
			),
			udpSniffer,
			&cfg.Runtime,
		)
		bindHandler := socks5.NewBindHandler(logging.WithScope(logger, "hnd"))

		return socks5.NewSOCKS5Proxy(
			logging.WithScope(logger, "srv"),
			resolver,
			ruleSet,
			connectHandler,
			bindHandler,
			udpAssociateHandler,
			tcpSniffer,
			udpSniffer,
			socks5.NewSOCKS5SystemNetwork(
				logging.WithScope(logger, "sys"),
				defaultRoute,
			),
			cfg.Startup.App.ListenAddr,
			&cfg.Runtime,
		), nil
	case config.AppModeTUN:
		if err != nil {
			return nil, fmt.Errorf("failed to get default route: %w", err)
		}
		logger.Info().
			Str("interface", defaultRoute.Iface.Name).
			Str("gateway", defaultRoute.Gateway.String()).
			Msg("determined default interface and gateway")

		// Get FIB ID from config (FreeBSD only, default to 1)
		fibID := cfg.Startup.App.FreebsdFIB

		tcpHandler := tun.NewTCPHandler(
			logging.WithScope(logger, "hnd"),
			desync.NewTLSDesyncer(tcpWriter, tcpSniffer),
			tcpSniffer,
			ruleSet,
			&cfg.Runtime,
		)

		udpHandler := tun.NewUDPHandler(
			logging.WithScope(logger, "hnd"),
			desync.NewUDPDesyncer(
				logging.WithScope(logger, "hnd"),
				udpWriter,
				udpSniffer,
			),
			udpSniffer,
			ruleSet,
			&cfg.Runtime,
		)

		sysNet, err := tun.NewTUNSystemNetwork(
			logging.WithScope(logger, "sys"),
			defaultRoute,
			fibID,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create sysnet: %w", err)
		}

		return tun.NewTUNServer(
			logging.WithScope(logger, "srv"),
			tcpHandler,
			udpHandler,
			tcpSniffer,
			udpSniffer,
			sysNet,
		), nil
	default:
		return nil, fmt.Errorf("unknown server mode: %s", cfg.Startup.App.Mode)
	}
}
