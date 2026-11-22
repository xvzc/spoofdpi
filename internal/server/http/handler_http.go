package http

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/dns"
	"github.com/xvzc/spoofdpi/internal/logging"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/proto"
	"github.com/xvzc/spoofdpi/internal/rule"
)

type HTTPHandler struct {
	logger     zerolog.Logger
	resolver   dns.Resolver
	ruleSet    *rule.RuleSet
	listenAddr net.TCPAddr
	cfg        *config.RuntimeConfig
}

func NewHTTPHandler(
	logger zerolog.Logger,
	resolver dns.Resolver,
	ruleSet *rule.RuleSet,
	listenAddr net.TCPAddr,
	cfg *config.RuntimeConfig,
) *HTTPHandler {
	return &HTTPHandler{
		logger:     logger,
		resolver:   resolver,
		ruleSet:    ruleSet,
		listenAddr: listenAddr,
		cfg:        cfg,
	}
}

// Handle serves one plain HTTP request read from lConn.
func (h *HTTPHandler) Handle(
	ctx context.Context,
	lConn net.Conn,
	req *proto.HTTPRequest,
) error {
	c := &httpConn{h: h, conn: lConn, req: req}
	return c.serve(ctx)
}

// httpConn is one plain HTTP request. It owns the remote connection it dials
// and closes it when serve returns. The request is the last one on the
// client connection, so that each later request comes on a new connection
// and gets its own destination and rule.
type httpConn struct {
	h      *HTTPHandler
	conn   net.Conn
	req    *proto.HTTPRequest
	logger zerolog.Logger

	dst     *netutil.Destination
	matched *config.Rule
	cfg     *config.RuntimeConfig
	rConn   net.Conn
}

func (c *httpConn) serve(ctx context.Context) error {
	c.logger = logging.WithLocalScope(ctx, c.h.logger, "http")

	if !c.selectDestination(ctx) || !c.checkDestination() {
		return nil
	}

	if err := c.dial(ctx); err != nil {
		return err
	}
	defer netutil.CloseConns(c.rConn)

	c.logger.Debug().Msgf("new remote conn -> %s", c.rConn.RemoteAddr())

	if err := c.forward(); err != nil {
		return err
	}

	return c.tunnel(ctx)
}

// selectDestination resolves the request's destination and selects its
// rule. It writes the failure reply and reports false when the request
// names no usable destination.
func (c *httpConn) selectDestination(ctx context.Context) bool {
	host := c.req.ExtractHost()
	port, err := c.req.ExtractPort()
	if err != nil {
		c.logger.Warn().Str("host", c.req.Host).Msg("failed to extract port")
		_ = proto.HTTPBadRequestResponse().Write(c.conn)
		return false
	}

	c.dst, c.matched, c.cfg, err = resolveDestination(
		ctx, c.logger, c.h.resolver, c.h.ruleSet, c.h.cfg, host, port,
	)
	if err != nil {
		_ = proto.HTTPBadGatewayResponse().Write(c.conn)
		c.logger.Error().Err(err).Msgf("dns lookup failed for %s", host)
		return false
	}

	return true
}

// checkDestination writes a 403 for a destination that is the proxy itself.
// It reports false when the request must not go on.
func (c *httpConn) checkDestination() bool {
	switch verifyDestination(c.logger, c.dst, c.matched, &c.h.listenAddr) {
	case destinationSelf:
		_ = proto.HTTPForbiddenResponse().Write(c.conn)
		return false
	case destinationBlocked:
		return false
	default:
		return true
	}
}

// dial connects to the destination, and writes a 502 when it can't.
func (c *httpConn) dial(ctx context.Context) error {
	rConn, err := netutil.DialFastest(
		ctx, c.dst, "tcp", netutil.DialOptions{Timeout: c.cfg.Conn.TCPTimeout},
	)
	if err != nil {
		_ = proto.HTTPBadGatewayResponse().Write(c.conn)
		return err
	}
	c.rConn = rConn

	return nil
}

// forward sends the request to the remote in the form a proxy sends it.
// Unless the request upgrades the connection to another protocol, it asks
// the remote to close the connection after its response.
func (c *httpConn) forward() error {
	if !c.req.IsUpgrade() {
		c.req.SetConnectionClose()
	}

	if err := c.req.WriteProxy(c.rConn); err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}

	return nil
}

// tunnel copies between the conns until either side closes, and then closes
// both. The remote closes after its response to a request forwarded with
// "Connection: close", which closes the client conn as well.
func (c *httpConn) tunnel(ctx context.Context) error {
	resCh := make(chan netutil.TransferResult, 2)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	startedAt := time.Now()
	go netutil.TunnelConns(ctx, resCh, c.conn, c.rConn, netutil.TunnelDirOut)
	go netutil.TunnelConns(ctx, resCh, c.rConn, c.conn, netutil.TunnelDirIn)

	return netutil.WaitForTunnelCompletion(
		ctx,
		c.logger,
		resCh,
		startedAt,
		netutil.DescribeRoute(c.conn, c.rConn),
		nil,
	)
}
