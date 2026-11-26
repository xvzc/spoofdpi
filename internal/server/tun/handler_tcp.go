package tun

import (
	"context"
	"errors"
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
	alerts   *server.TLSAlertWatcher
	// firstByteWait is how long Handle waits for the first byte of the
	// client to tell TLS from other TCP.
	firstByteWait time.Duration
}

// firstByteWait is the default of TCPHandler.firstByteWait. A client on
// the TUN sends its ClientHello as soon as the local stack accepts the
// connection, so a second is ample; a client of a protocol where the
// server speaks first is relayed after it.
const firstByteWait = time.Second

func NewTCPHandler(
	logger zerolog.Logger,
	desyncer *desync.TLSDesyncer,
	alerts *server.TLSAlertWatcher,
	ruleSet *rule.RuleSet,
	cfg *config.RuntimeConfig,
) *TCPHandler {
	return &TCPHandler{
		logger:   logger,
		ruleSet:  ruleSet,
		cfg:      cfg,
		desyncer: desyncer,
		alerts:   alerts,

		firstByteWait: firstByteWait,
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

	// Wait a while for the first byte, to tell TLS from other TCP. A
	// client that sends nothing by then may be waiting for the server to
	// speak first, as in SSH, and is relayed as other TCP.
	_ = lConn.SetReadDeadline(time.Now().Add(h.firstByteWait))
	lBufferedConn := netutil.NewBufferedConn(lConn)
	buf, err := lBufferedConn.Peek(1)
	_ = lConn.SetReadDeadline(time.Time{})
	// gonet reports the deadline as a net.Error that times out, not as
	// os.ErrDeadlineExceeded.
	var netErr net.Error
	if err != nil && (!errors.As(err, &netErr) || !netErr.Timeout()) {
		return
	}

	// Check if it's a TLS Handshake (Content Type 0x16)
	if err == nil && buf[0] == 0x16 {
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

	rConn, err := netutil.DialFastest(ctx, dst, "tcp", netutil.DialOptions{
		Timeout: cfg.Conn.TCPTimeout,
		Bind:    sysNet.BindDialer,
	})
	if err != nil {
		logger.Error().Msgf("failed to dial %v", err)
		return
	}

	logger.Debug().
		Str("local", rConn.LocalAddr().String()).
		Str("remote", rConn.RemoteAddr().String()).
		Msg("new remote conn")

	err = netutil.RelayBidirectional(
		ctx,
		logger,
		lBufferedConn,
		rConn,
		netutil.RelayOptions{},
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

	// The SNI is matched as the domain name.
	cfg, ok := h.selectRule(logger, dst.Host, dst)
	if !ok {
		return nil
	}

	// Dial Remote
	h.desyncer.PrepareHopTrack(dst.Addrs, &cfg.HTTPS)

	rConn, err := netutil.DialFastest(ctx, dst, "tcp", netutil.DialOptions{
		Timeout: cfg.Conn.TCPTimeout,
		Bind:    sysNet.BindDialer,
	})
	if err != nil {
		return err
	}
	defer netutil.CloseConns(rConn)

	logger.Debug().
		Str("local", rConn.LocalAddr().String()).
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
	// dst.Host is the SNI here.
	inspectReply := h.alerts.Inspector(logger, rConn, dst.Host, "")

	return netutil.RelayBidirectional(ctx, logger, lConn, rConn, netutil.RelayOptions{
		OnFirstReply: inspectReply,
	})
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
