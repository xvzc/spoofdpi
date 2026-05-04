package http

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"time"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/desync"
	"github.com/xvzc/spoofdpi/internal/logging"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/packet"
	"github.com/xvzc/spoofdpi/internal/proto"
)

type HTTPSHandler struct {
	logger   zerolog.Logger
	desyncer *desync.TLSDesyncer
	sniffer  packet.Sniffer
	rt       *config.RuntimeConfig
}

func NewHTTPSHandler(
	logger zerolog.Logger,
	desyncer *desync.TLSDesyncer,
	sniffer packet.Sniffer,
	rt *config.RuntimeConfig,
) *HTTPSHandler {
	return &HTTPSHandler{
		logger:   logger,
		desyncer: desyncer,
		sniffer:  sniffer,
		rt:       rt,
	}
}

func (h *HTTPSHandler) HandleRequest(
	ctx context.Context,
	lConn net.Conn,
	dst *netutil.Destination,
	rule *config.Rule,
) error {
	rt := h.rt
	if rule != nil {
		rt = &rule.Config
	}

	logger := logging.WithLocalScope(ctx, h.logger, "handshake")

	// 1. Send 200 Connection Established
	if err := proto.HTTPConnectionEstablishedResponse().Write(lConn); err != nil {
		if !netutil.IsConnectionResetByPeer(err) && !errors.Is(err, io.EOF) {
			logger.Trace().Err(err).Msgf("proxy handshake error")
			return fmt.Errorf("failed to handle proxy handshake: %w", err)
		}
		return nil
	}
	logger.Trace().Msgf("sent 200 connection established -> %s", lConn.RemoteAddr())

	// 2. Tunnel
	return h.tunnel(ctx, lConn, dst, rt)
}

func (h *HTTPSHandler) tunnel(
	ctx context.Context,
	lConn net.Conn,
	dst *netutil.Destination,
	rt *config.RuntimeConfig,
) error {
	if h.sniffer != nil && rt.HTTPS.FakeCount > 0 {
		h.sniffer.RegisterUntracked(dst.Addrs)
	}

	logger := logging.WithLocalScope(ctx, h.logger, "https")

	rConn, err := netutil.DialFastest(ctx, dst, "tcp", rt.Conn.TCPTimeout, nil)
	if err != nil {
		return err
	}
	defer netutil.CloseConns(rConn)

	logger.Debug().Msgf("new remote conn -> %s", rConn.RemoteAddr())

	// Read the first message from the client (expected to be ClientHello)
	tlsMsg, err := proto.ReadTLSMessage(lConn)
	if err != nil {
		if err == io.EOF || err.Error() == "unexpected EOF" {
			return nil
		}
		logger.Trace().Err(err).Msgf("failed to read first message from client")
		return err
	}

	logger.Debug().
		Int("len", tlsMsg.Len()).
		Msgf("client hello received <- %s", lConn.RemoteAddr())

	if !tlsMsg.IsClientHello() {
		logger.Trace().Int("len", tlsMsg.Len()).Msg("not a client hello. aborting")
		return nil
	}

	// Send ClientHello to the remote server (with desync if configured)
	n, err := h.sendClientHello(ctx, rConn, tlsMsg, &rt.HTTPS)
	if err != nil {
		return fmt.Errorf("failed to send client hello: %w", err)
	}

	logger.Debug().
		Int("len", n).
		Msgf("sent client hello -> %s", rConn.RemoteAddr())

	// Start bi-directional tunneling
	resCh := make(chan netutil.TransferResult, 2)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	startedAt := time.Now()
	go netutil.TunnelConns(ctx, resCh, lConn, rConn, netutil.TunnelDirOut)
	go netutil.TunnelConns(ctx, resCh, rConn, lConn, netutil.TunnelDirIn)

	handleErrs := func(errs []error) error {
		if len(errs) == 0 {
			return nil
		}

		if slices.ContainsFunc(errs, netutil.IsConnectionResetByPeer) {
			return netutil.ErrBlocked
		}

		return errs[0]
	}

	return netutil.WaitForTunnelCompletion(
		ctx,
		logger,
		resCh,
		startedAt,
		netutil.DescribeRoute(lConn, rConn),
		handleErrs,
	)
}

func (h *HTTPSHandler) sendClientHello(
	ctx context.Context,
	rConn net.Conn,
	msg *proto.TLSMessage,
	opts *config.HTTPSOptions,
) (int, error) {
	return h.desyncer.Desync(ctx, h.logger, rConn, msg, opts)
}
