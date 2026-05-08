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
	"github.com/xvzc/spoofdpi/internal/proto"
)

type HTTPSHandler struct {
	logger   zerolog.Logger
	desyncer *desync.TLSDesyncer
	cfg      *config.RuntimeConfig
}

func NewHTTPSHandler(
	logger zerolog.Logger,
	desyncer *desync.TLSDesyncer,
	cfg *config.RuntimeConfig,
) *HTTPSHandler {
	return &HTTPSHandler{
		logger:   logger,
		desyncer: desyncer,
		cfg:      cfg,
	}
}

func (h *HTTPSHandler) HandleRequest(
	ctx context.Context,
	lConn net.Conn,
	dst *netutil.Destination,
	rule *config.Rule,
) error {
	cfg := h.cfg
	if rule != nil {
		cfg = &rule.Config
	}

	h.desyncer.PrepareHopTrack(dst.Addrs, &cfg.HTTPS)

	logger := logging.WithLocalScope(ctx, h.logger, "https")

	// 1. Send 200 Connection Established
	if err := proto.HTTPConnectionEstablishedResponse().Write(lConn); err != nil {
		if !netutil.IsConnectionResetByPeer(err) && !errors.Is(err, io.EOF) {
			logger.Trace().Err(err).Msgf("proxy handshake error")
			return fmt.Errorf("failed to handle proxy handshake: %w", err)
		}
		return nil
	}
	logger.Trace().Msgf("sent 200 connection established -> %s", lConn.RemoteAddr())

	// 2. Dial remote
	rConn, err := netutil.DialFastest(ctx, dst, "tcp", cfg.Conn.TCPTimeout, nil)
	if err != nil {
		return err
	}
	defer netutil.CloseConns(rConn)

	logger.Debug().Msgf("new remote conn -> %s", rConn.RemoteAddr())

	// 3. Read ClientHello
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

	// 4. Send ClientHello with desync
	n, err := h.desyncer.Desync(ctx, h.logger, rConn, tlsMsg, &cfg.HTTPS)
	if err != nil {
		return fmt.Errorf("failed to send client hello: %w", err)
	}

	logger.Debug().Int("len", n).Msgf("sent client hello -> %s", rConn.RemoteAddr())

	// 5. Tunnel
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
