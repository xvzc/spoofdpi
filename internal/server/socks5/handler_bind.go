package socks5

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/logging"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/proto"
)

type BindHandler struct {
	logger zerolog.Logger
}

func NewBindHandler(logger zerolog.Logger) *BindHandler {
	return &BindHandler{
		logger: logger,
	}
}

func (h *BindHandler) Handle(
	ctx context.Context,
	conn net.Conn,
	req *proto.SOCKS5Request,
) error {
	logger := logging.WithLocalScope(ctx, h.logger, "bind")

	// Listen on the same IP as the proxy's client-facing address so the
	// advertised address in the first reply is reachable by the client.
	localIP := conn.LocalAddr().(*net.TCPAddr).IP
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: localIP, Port: 0})
	if err != nil {
		logger.Error().Err(err).Msg("failed to create bind listener")
		_ = proto.SOCKS5FailureResponse().Write(conn)
		return err
	}
	defer func() { _ = listener.Close() }()

	lAddr := listener.Addr().(*net.TCPAddr)

	logger.Debug().Str("addr", lAddr.String()).Msg("new listener")

	// 1. First reply: advertise listening address
	if err := proto.SOCKS5SuccessResponse().
		Bind(lAddr.IP).
		Port(lAddr.Port).
		Write(conn); err != nil {
		logger.Error().Err(err).Msg("failed to write first bind reply")
		return err
	}

	logger.Debug().Str("bind_addr", lAddr.String()).Msg("waiting for incoming connection")

	// Close the listener (unblocking Accept) if the client TCP connection drops.
	// The monitoring goroutine must exit before tunneling begins to avoid
	// stealing bytes; stopMonitor + SetReadDeadline achieves this.
	stopMonitor := make(chan struct{})
	var monitorWg sync.WaitGroup
	monitorWg.Add(1)
	go func() {
		defer monitorWg.Done()
		b := [1]byte{}
		for {
			_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			_, err := conn.Read(b[:])
			if err != nil {
				select {
				case <-stopMonitor:
					return // accept succeeded; don't touch listener
				default:
				}
				// Read deadline expires every 200ms while waiting for Accept;
				// that's expected — keep polling. Only a real drop closes the listener.
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				_ = listener.Close()
				return
			}
			select {
			case <-stopMonitor:
				return
			default:
			}
		}
	}()

	// 2. Accept with context cancellation support
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := listener.Accept()
		ch <- result{c, err}
	}()

	var remoteConn net.Conn
	select {
	case <-ctx.Done():
		// Close the listener to unblock Accept, then drain ch to close any
		// conn that was accepted concurrently before the listener closed.
		_ = listener.Close()
		if res := <-ch; res.conn != nil {
			_ = res.conn.Close()
		}
		return ctx.Err()
	case res := <-ch:
		if res.err != nil {
			logger.Error().Err(res.err).Msg("failed to accept incoming connection")
			_ = proto.SOCKS5FailureResponse().Write(conn)
			return res.err
		}
		remoteConn = res.conn
	}
	defer netutil.CloseConns(remoteConn)

	// Stop monitoring and wait for the goroutine to exit before tunneling.
	close(stopMonitor)
	_ = conn.SetReadDeadline(time.Now()) // unblock any in-progress Read immediately
	monitorWg.Wait()
	_ = conn.SetReadDeadline(time.Time{}) // restore for tunneling

	rAddr := remoteConn.RemoteAddr().(*net.TCPAddr)

	// 3. Verify connecting host matches DST.ADDR from the BIND request (RFC 1928)
	if req.IP != nil && !req.IP.IsUnspecified() && !rAddr.IP.Equal(req.IP) {
		logger.Warn().
			Str("expected", req.IP.String()).
			Str("actual", rAddr.IP.String()).
			Msg("rejecting connection from unexpected host")
		_ = proto.SOCKS5FailureResponse().Write(conn)
		return fmt.Errorf("bind: unexpected connecting host %s", rAddr.IP)
	}

	logger.Debug().Str("remote_addr", rAddr.String()).Msg("accepted incoming connection")

	// 4. Second reply: report the connecting host's address
	if err := proto.SOCKS5SuccessResponse().
		Bind(rAddr.IP).
		Port(rAddr.Port).
		Write(conn); err != nil {
		logger.Error().Err(err).Msg("failed to write second bind reply")
		return err
	}

	// 5. Tunnel
	resCh := make(chan netutil.TransferResult, 2)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	startedAt := time.Now()
	go netutil.TunnelConns(ctx, resCh, remoteConn, conn, netutil.TunnelDirOut)
	go netutil.TunnelConns(ctx, resCh, conn, remoteConn, netutil.TunnelDirIn)

	return netutil.WaitForTunnelCompletion(
		ctx,
		logger,
		resCh,
		startedAt,
		netutil.DescribeRoute(conn, remoteConn),
		nil,
	)
}
