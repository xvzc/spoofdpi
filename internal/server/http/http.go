package http

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/logging"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/proto"
	"github.com/xvzc/spoofdpi/internal/server"
)

type HTTPProxy struct {
	logger zerolog.Logger

	httpHandler  *HTTPHandler
	httpsHandler *HTTPSHandler
	listenAddr   net.TCPAddr

	listener *net.TCPListener
	conns    server.ConnTracker
}

func NewHTTPProxy(
	logger zerolog.Logger,
	httpHandler *HTTPHandler,
	httpsHandler *HTTPSHandler,
	listenAddr net.TCPAddr,
) server.Server {
	return &HTTPProxy{
		logger:       logger,
		httpHandler:  httpHandler,
		httpsHandler: httpsHandler,
		listenAddr:   listenAddr,
	}
}

func (p *HTTPProxy) Listen(_ context.Context) error {
	listener, err := net.ListenTCP("tcp", &p.listenAddr)
	if err != nil {
		return fmt.Errorf(
			"error creating listener on %s: %w",
			p.listenAddr.String(),
			err,
		)
	}
	p.listener = listener

	return nil
}

func (p *HTTPProxy) Serve(ctx context.Context) error {
	// Closing the listener when ctx ends makes Accept return net.ErrClosed.
	stop := context.AfterFunc(ctx, func() { _ = p.listener.Close() })
	defer stop()

	var backoff server.Backoff
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				break
			}

			p.logger.Error().Err(err).Msgf("failed to accept new connection")
			backoff.Wait(ctx)

			continue
		}
		backoff.Reset()

		p.conns.Go(ctx, conn, func(ctx context.Context) {
			p.handleNewConnection(ctx, conn)
		})
	}

	if !p.conns.Wait(server.ShutdownSafetyTimeout) {
		p.logger.Warn().
			Int64("count", p.conns.Active()).
			Msg("connections still open at shutdown")
	}

	return nil
}

func (p *HTTPProxy) SetupNetworkJobs(ctx context.Context) (string, error) {
	if err := server.SetupSystemProxy(
		ctx,
		fmt.Sprintf("PROXY 127.0.0.1:%d", p.listenAddr.Port),
		StateFile,
	); err != nil {
		return "", err
	}
	return StateFile, nil
}

func (p *HTTPProxy) Addr() string {
	return p.listenAddr.String()
}

func (p *HTTPProxy) handleNewConnection(ctx context.Context, conn net.Conn) {
	logger := logging.WithLocalScope(ctx, p.logger, "conn_init")

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer netutil.CloseConns(conn)

	req, err := proto.ReadHttpRequest(conn)
	if err != nil {
		// The server closes conn and cancels ctx when it shuts down.
		shutdown := ctx.Err() != nil || errors.Is(err, net.ErrClosed)
		if err != io.EOF && !shutdown {
			logger.Warn().Err(err).Msg("failed to read http request")
		}

		return
	}

	logger.Debug().Str("from", conn.RemoteAddr().String()).Str("host", req.Host).
		Msg("new request")

	if !req.IsValidMethod() {
		logger.Warn().Str("method", req.Method).Msg("unsupported method. abort")
		_ = proto.HTTPNotImplementedResponse().Write(conn)

		return
	}

	logger.Debug().
		Str("method", req.Method).
		Str("from", conn.RemoteAddr().String()).
		Msg("new request")

	var handleErr error
	if req.IsConnectMethod() {
		handleErr = p.httpsHandler.Handle(ctx, conn, req)
	} else {
		handleErr = p.httpHandler.Handle(ctx, conn, req)
	}

	if handleErr == nil { // Early exit if no error found
		return
	}

	logger.Warn().Err(handleErr).Msg("error handling request")
}
