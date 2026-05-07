package socks5

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/desync"
	"github.com/xvzc/spoofdpi/internal/logging"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/packet"
	"github.com/xvzc/spoofdpi/internal/proto"
)

type ConnectHandler struct {
	logger     zerolog.Logger
	desyncer   *desync.TLSDesyncer
	sniffer    packet.Sniffer
	listenAddr net.TCPAddr
	cfg        *config.RuntimeConfig
}

func NewConnectHandler(
	logger zerolog.Logger,
	desyncer *desync.TLSDesyncer,
	sniffer packet.Sniffer,
	listenAddr net.TCPAddr,
	cfg *config.RuntimeConfig,
) *ConnectHandler {
	return &ConnectHandler{
		logger:     logger,
		desyncer:   desyncer,
		sniffer:    sniffer,
		listenAddr: listenAddr,
		cfg:        cfg,
	}
}

func (h *ConnectHandler) Handle(
	ctx context.Context,
	lConn net.Conn,
	req *proto.SOCKS5Request,
	dst *netutil.Destination,
	rule *config.Rule,
) error {
	cfg := h.cfg
	if rule != nil {
		cfg = &rule.Config
	}

	logger := logging.WithLocalScope(ctx, h.logger, "connect")

	// 1. Validate destination
	ok, err := dst.IsValid(&h.listenAddr)
	if err != nil {
		logger.Debug().Err(err).Msg("error determining if valid destination")
		if !ok {
			_ = proto.SOCKS5FailureResponse().Write(lConn)
			return err
		}
	}

	// 2. Check if blocked
	if rule != nil && rule.Block {
		logger.Debug().Msg("request is blocked by policy")
		_ = proto.SOCKS5FailureResponse().Write(lConn)
		return netutil.ErrBlocked
	}

	// 3. Dial remote
	if h.sniffer != nil && !cfg.HTTPS.Skip && cfg.HTTPS.FakeCount > 0 {
		h.sniffer.RegisterUntracked(dst.Addrs)
	}

	rConn, err := netutil.DialFastest(ctx, dst, "tcp", cfg.Conn.TCPTimeout, nil)
	if err != nil {
		_ = proto.SOCKS5FailureResponse().Write(lConn)
		return err
	}
	defer netutil.CloseConns(rConn)

	// 4. Send success response
	if err := proto.SOCKS5SuccessResponse().
		Bind(net.IPv4zero).
		Port(0).
		Write(lConn); err != nil {
		logger.Error().Err(err).Msg("failed to write socks5 success reply")
		return err
	}

	logger.Debug().Msgf("new remote conn -> %s", rConn.RemoteAddr())

	// 5. Peek for TLS
	bufConn := netutil.NewBufferedConn(lConn)
	b, err := bufConn.Peek(1)

	if err == nil && b[0] == byte(proto.TLSHandshake) {
		// 6. Read ClientHello
		tlsMsg, err := proto.ReadTLSMessage(bufConn)
		if err != nil {
			if err == io.EOF || err.Error() == "unexpected EOF" {
				return nil
			}
			logger.Trace().Err(err).Msgf("failed to read first message from client")
			return err
		}

		if tlsMsg.IsClientHello() {
			// 7. Send ClientHello with desync
			logger.Debug().
				Int("len", tlsMsg.Len()).
				Msgf("client hello received <- %s", lConn.RemoteAddr())
			var n int
			if cfg.HTTPS.Skip {
				n, err = rConn.Write(tlsMsg.Raw())
			} else {
				n, err = h.desyncer.Desync(ctx, h.logger, rConn, tlsMsg, &cfg.HTTPS)
			}
			if err != nil {
				return fmt.Errorf("failed to send client hello: %w", err)
			}
			logger.Debug().Int("len", n).Msgf("sent client hello -> %s", rConn.RemoteAddr())
		} else {
			logger.Debug().
				Int("len", tlsMsg.Len()).
				Msg("not a client hello. fallback to pure tcp")
			if _, err := rConn.Write(tlsMsg.Raw()); err != nil {
				return fmt.Errorf("failed to write initial bytes to remote: %w", err)
			}
		}
	} else {
		logger.Debug().Msg("not a tls handshake. fallback to pure tcp")
	}

	// 8. Tunnel
	resCh := make(chan netutil.TransferResult, 2)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	startedAt := time.Now()
	go netutil.TunnelConns(ctx, resCh, rConn, bufConn, netutil.TunnelDirOut)
	go netutil.TunnelConns(ctx, resCh, bufConn, rConn, netutil.TunnelDirIn)

	return netutil.WaitForTunnelCompletion(
		ctx,
		logger,
		resCh,
		startedAt,
		netutil.DescribeRoute(bufConn, rConn),
		nil,
	)
}
