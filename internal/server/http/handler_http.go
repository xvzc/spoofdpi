package http

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/logging"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/proto"
)

type HTTPHandler struct {
	logger zerolog.Logger
}

func NewHTTPHandler(logger zerolog.Logger) *HTTPHandler {
	return &HTTPHandler{
		logger: logger,
	}
}

func (h *HTTPHandler) HandleRequest(
	ctx context.Context,
	lConn net.Conn, // Use the net.Conn interface, not a concrete *net.TCPConn.
	req *proto.HTTPRequest, // Assumes HttpRequest is a custom type for request parsing.
	dst *netutil.Destination,
	rule *config.Rule,
) error {
	logger := logging.WithLocalScope(ctx, h.logger, "http")

	rConn, err := netutil.DialFastest(ctx, dst, "tcp", 0, nil)
	if err != nil {
		_ = proto.HTTPBadGatewayResponse().Write(lConn)
		return err
	}

	// Ensure the remote connection is also closed on exit.
	defer netutil.CloseConns(rConn)

	logger.Debug().Msgf("new remote conn -> %s", rConn.RemoteAddr())

	// Assumes our custom HttpRequest type has a WriteProxy method
	// (like net/http.Request.WriteProxy) that correctly formats the
	// request for the origin server (e.g., "GET /path" instead of "GET http://...").
	if err := req.WriteProxy(rConn); err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}

	// Start bi-directional tunneling
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
