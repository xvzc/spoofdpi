package socks5

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/logging"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/proto"
)

// bindAcceptTimeout bounds the wait for the incoming connection. RFC 1928
// sets no limit, but SOCKS4 requires one, with 2 minutes as its example; a
// client that drops while waiting is otherwise only noticed at shutdown.
const bindAcceptTimeout = 2 * time.Minute

type BindHandler struct {
	logger zerolog.Logger

	// acceptTimeout bounds the wait for the incoming connection.
	acceptTimeout time.Duration
}

func NewBindHandler(logger zerolog.Logger) *BindHandler {
	return &BindHandler{
		logger:        logger,
		acceptTimeout: bindAcceptTimeout,
	}
}

func (h *BindHandler) Handle(
	ctx context.Context,
	conn net.Conn,
	req *proto.SOCKS5Request,
) error {
	c := &bindConn{h: h, conn: conn, req: req}
	return c.serve(ctx)
}

// bindConn is one BIND request. It owns the listener it opens and the
// incoming connection it accepts, and closes them when serve returns.
type bindConn struct {
	h      *BindHandler
	conn   net.Conn
	req    *proto.SOCKS5Request
	logger zerolog.Logger

	listener *net.TCPListener
	remote   net.Conn
}

func (c *bindConn) serve(ctx context.Context) error {
	c.logger = logging.WithLocalScope(ctx, c.h.logger, "bind")

	if err := c.listen(); err != nil {
		return err
	}
	defer func() { _ = c.listener.Close() }()

	lAddr := c.listener.Addr().(*net.TCPAddr)

	c.logger.Debug().Str("addr", lAddr.String()).Msg("new listener")

	// 1. First reply: advertise listening address
	if err := proto.SOCKS5SuccessResponse().
		Bind(lAddr.IP).
		Port(lAddr.Port).
		Write(c.conn); err != nil {
		c.logger.Error().Err(err).Msg("failed to write first bind reply")
		return err
	}

	c.logger.Debug().
		Str("bind_addr", lAddr.String()).
		Msg("waiting for incoming connection")

	// 2. Accept
	if err := c.accept(ctx); err != nil {
		return err
	}
	defer netutil.CloseConns(c.remote)

	rAddr := c.remote.RemoteAddr().(*net.TCPAddr)

	// 3. Verify connecting host matches DST.ADDR from the BIND request (RFC 1928)
	if c.req.IP != nil && !c.req.IP.IsUnspecified() && !rAddr.IP.Equal(c.req.IP) {
		c.logger.Warn().
			Str("expected", c.req.IP.String()).
			Str("actual", rAddr.IP.String()).
			Msg("rejecting connection from unexpected host")
		_ = proto.SOCKS5FailureResponse().Write(c.conn)
		return fmt.Errorf("bind: unexpected connecting host %s", rAddr.IP)
	}

	c.logger.Debug().
		Str("remote_addr", rAddr.String()).
		Msg("accepted incoming connection")

	// 4. Second reply: report the connecting host's address
	if err := proto.SOCKS5SuccessResponse().
		Bind(rAddr.IP).
		Port(rAddr.Port).
		Write(c.conn); err != nil {
		c.logger.Error().Err(err).Msg("failed to write second bind reply")
		return err
	}

	// 5. Tunnel
	return c.tunnel(ctx)
}

// listen opens the listener for the incoming connection, and writes the
// failure reply when it can't.
func (c *bindConn) listen() error {
	// Listen on the same IP as the proxy's client-facing address so the
	// advertised address in the first reply is reachable by the client.
	localIP := c.conn.LocalAddr().(*net.TCPAddr).IP
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: localIP, Port: 0})
	if err != nil {
		c.logger.Error().Err(err).Msg("failed to create bind listener")
		_ = proto.SOCKS5FailureResponse().Write(c.conn)
		return err
	}
	c.listener = listener

	return nil
}

// accept waits for the incoming connection until ctx is cancelled or the
// accept timeout passes, and writes the failure reply when it can't accept.
func (c *bindConn) accept(ctx context.Context) error {
	_ = c.listener.SetDeadline(time.Now().Add(c.h.acceptTimeout))

	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := c.listener.Accept()
		ch <- result{conn, err}
	}()

	select {
	case <-ctx.Done():
		// Close the listener to unblock Accept, then drain ch to close any
		// conn that was accepted concurrently before the listener closed.
		_ = c.listener.Close()
		if res := <-ch; res.conn != nil {
			_ = res.conn.Close()
		}
		return ctx.Err()
	case res := <-ch:
		if res.err != nil {
			c.logger.Error().Err(res.err).Msg("failed to accept incoming connection")
			_ = proto.SOCKS5FailureResponse().Write(c.conn)
			return res.err
		}
		c.remote = res.conn
	}

	return nil
}

func (c *bindConn) tunnel(ctx context.Context) error {
	resCh := make(chan netutil.TransferResult, 2)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	startedAt := time.Now()
	go netutil.TunnelConns(ctx, resCh, c.remote, c.conn, netutil.TunnelDirOut)
	go netutil.TunnelConns(ctx, resCh, c.conn, c.remote, netutil.TunnelDirIn)

	return netutil.WaitForTunnelCompletion(
		ctx,
		c.logger,
		resCh,
		startedAt,
		netutil.DescribeRoute(c.conn, c.remote),
		nil,
	)
}
