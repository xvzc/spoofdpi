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

	// Addr-based rule matching using the destination IP
	cfg := h.cfg
	if h.ruleSet != nil {
		q := []rule.Query{{Type: rule.MatchTypeAddr, Value: dst.Addrs[0].String()}}
		if addrRule := h.ruleSet.Search(q); addrRule != nil {
			logger.Trace().RawJSON("summary", addrRule.JSON()).Msg("addr match")
			cfg = &addrRule.Config
		}
	}

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
		if err := h.handleTLS(ctx, logger, lBufferedConn, dst, cfg, sysNet); err != nil {
			logger.Debug().Err(err).Msg("tls handler failed")
		}
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
	cfg *config.RuntimeConfig,
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

	// Domain-based matching overrides addr-based cfg when SNI is available
	if h.ruleSet != nil && dst.Host != "" {
		q := []rule.Query{{Type: rule.MatchTypeDomain, Value: dst.Host}}
		if domainRule := h.ruleSet.Search(q); domainRule != nil {
			logger.Trace().RawJSON("summary", domainRule.JSON()).Msg("domain match")
			cfg = &domainRule.Config
		}
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
	if _, err := h.desyncer.Desync(ctx, rConn, tlsMsg, &cfg.HTTPS); err != nil {
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
