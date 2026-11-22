package tun

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/desync"
	"github.com/xvzc/spoofdpi/internal/logging"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/proto"
	"github.com/xvzc/spoofdpi/internal/rule"
	"github.com/xvzc/spoofdpi/internal/server"
)

type TCPHandler struct {
	logger   zerolog.Logger
	ruleSet  *rule.RuleSet
	cfg      *config.RuntimeConfig
	desyncer *desync.TLSDesyncer
}

func NewTCPHandler(
	logger zerolog.Logger,
	desyncer *desync.TLSDesyncer,
	ruleSet *rule.RuleSet,
	cfg *config.RuntimeConfig,
) *TCPHandler {
	return &TCPHandler{
		logger:   logger,
		ruleSet:  ruleSet,
		cfg:      cfg,
		desyncer: desyncer,
	}
}

func (h *TCPHandler) Handle(
	ctx context.Context,
	lConn net.Conn,
	dst *netutil.Destination,
	sysNet TUNSystemNetwork,
) {
	defer netutil.CloseConns(lConn)

	logger := logging.WithLocalScope(ctx, h.logger, "tcp")

	// Set a read deadline for the first byte to avoid hanging indefinitely
	_ = lConn.SetReadDeadline(time.Now().Add(1 * time.Second))

	lBufferedConn := netutil.NewBufferedConn(lConn)
	buf, err := lBufferedConn.Peek(1)
	if err != nil {
		return
	}

	// Reset deadline
	_ = lConn.SetReadDeadline(time.Time{})

	// Check if it's a TLS Handshake (Content Type 0x16)
	if buf[0] == 0x16 {
		logger.Debug().Msg("detected tls handshake")
		if err := h.handleTLS(
			ctx,
			logger,
			lBufferedConn,
			dst,
			sysNet,
		); err != nil {
			logger.Debug().Err(err).Msg("tls handler failed")
		}
		return
	}

	cfg, ok := h.selectRule(logger, "", dst)
	if !ok {
		return
	}

	rConn, err := netutil.DialFastest(
		ctx, dst, "tcp", cfg.Conn.TCPTimeout, sysNet.BindDialer,
	)
	if err != nil {
		logger.Error().Msgf("failed to dial %v", err)
		return
	}

	logger.Debug().Msgf("new remote conn -> %s", rConn.RemoteAddr())

	resCh := make(chan netutil.TransferResult, 2)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	startedAt := time.Now()
	go netutil.TunnelConns(ctx, resCh, lBufferedConn, rConn, netutil.TunnelDirOut)
	go netutil.TunnelConns(ctx, resCh, rConn, lBufferedConn, netutil.TunnelDirIn)

	err = netutil.WaitForTunnelCompletion(
		ctx,
		logger,
		resCh,
		startedAt,
		netutil.DescribeRoute(lConn, rConn),
		nil,
	)
	if err != nil {
		logger.Error().Err(err).Msg("error handling request")
	}
}

func (h *TCPHandler) handleTLS(
	ctx context.Context,
	logger zerolog.Logger,
	lConn net.Conn,
	dst *netutil.Destination,
	sysNet TUNSystemNetwork,
) error {
	// Read ClientHello
	tlsMsg, err := proto.ReadTLSMessage(lConn)
	if err != nil {
		return err
	}

	if !tlsMsg.IsClientHello() {
		return fmt.Errorf("not a client hello")
	}

	// Extract SNI
	start, end, err := tlsMsg.ExtractSNIOffset()
	if err != nil {
		return fmt.Errorf("failed to extract sni: %w", err)
	}
	dst.Host = string(tlsMsg.Raw()[start:end])

	logger.Trace().Str("value", dst.Host).Msg("extracted sni field")

	// The SNI is matched as the domain name.
	cfg, ok := h.selectRule(logger, dst.Host, dst)
	if !ok {
		return nil
	}

	// Dial Remote
	h.desyncer.PrepareHopTrack(dst.Addrs, &cfg.HTTPS)

	rConn, err := netutil.DialFastest(
		ctx, dst, "tcp", cfg.Conn.TCPTimeout, sysNet.BindDialer,
	)
	if err != nil {
		return err
	}
	defer netutil.CloseConns(rConn)

	logger.Debug().
		Msgf("new remote conn (%s -> %s)", lConn.RemoteAddr(), rConn.RemoteAddr())

	// Send ClientHello with Desync
	if _, err := h.desyncer.Desync(
		ctx,
		rConn,
		tlsMsg,
		&cfg.HTTPS,
		&cfg.Conn,
	); err != nil {
		return err
	}

	// Tunnel rest
	resCh := make(chan netutil.TransferResult, 2)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	startedAt := time.Now()
	go netutil.TunnelConns(ctx, resCh, lConn, rConn, netutil.TunnelDirOut)
	go netutil.TunnelConns(ctx, resCh, rConn, lConn, netutil.TunnelDirIn)

	return netutil.WaitForTunnelCompletion(
		ctx,
		logger,
		resCh,
		startedAt,
		netutil.DescribeRoute(lConn, rConn),
		nil,
	)
}

// selectRule selects the rule for dst, matching name as its domain name
// when it is not empty, and returns the config to apply. ok is false when
// the rule blocks the connection, so it must not be dialed.
func (h *TCPHandler) selectRule(
	logger zerolog.Logger,
	name string,
	dst *netutil.Destination,
) (cfg *config.RuntimeConfig, ok bool) {
	matched, cfg := server.SelectRule(h.ruleSet, h.cfg, name, dst.Addrs)
	if matched != nil {
		logger.Trace().RawJSON("summary", matched.JSON()).Msg("match")
	}
	if matched != nil && matched.Block {
		logger.Debug().Msg("request is blocked by policy")
		return cfg, false
	}

	return cfg, true
}
