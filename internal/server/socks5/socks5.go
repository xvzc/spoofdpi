package socks5

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/logging"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/proto"
	"github.com/xvzc/spoofdpi/internal/server"
)

type SOCKS5Proxy struct {
	logger zerolog.Logger

	connectHandler      *ConnectHandler
	bindHandler         *BindHandler
	udpAssociateHandler *UdpAssociateHandler
	listenAddr          net.TCPAddr
	// requestTimeout bounds the wait for the greeting and the request of
	// a connection. Zero means no bound.
	requestTimeout time.Duration

	listener *net.TCPListener
	conns    server.ConnTracker
}

func NewSOCKS5Proxy(
	logger zerolog.Logger,
	connectHandler *ConnectHandler,
	bindHandler *BindHandler,
	udpAssociateHandler *UdpAssociateHandler,
	listenAddr net.TCPAddr,
	requestTimeout time.Duration,
) server.Server {
	return &SOCKS5Proxy{
		logger:              logger,
		connectHandler:      connectHandler,
		bindHandler:         bindHandler,
		udpAssociateHandler: udpAssociateHandler,
		listenAddr:          listenAddr,
		requestTimeout:      requestTimeout,
	}
}

func (p *SOCKS5Proxy) Listen(_ context.Context) error {
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

func (p *SOCKS5Proxy) Serve(ctx context.Context) error {
	// Closing the listener when ctx ends makes Accept return net.ErrClosed.
	stop := context.AfterFunc(ctx, func() { _ = p.listener.Close() })
	defer stop()

	var backoff server.Backoff
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				break // Normal shutdown
			}

			p.logger.Error().Err(err).Msg("failed to accept new connection")
			backoff.Wait(ctx)

			continue
		}
		backoff.Reset()

		p.conns.Go(ctx, conn, func(ctx context.Context) {
			p.handleConnection(ctx, conn)
		})
	}

	if !p.conns.Wait(server.ShutdownSafetyTimeout) {
		p.logger.Warn().
			Int64("count", p.conns.Active()).
			Msg("connections still open at shutdown")
	}

	return nil
}

func (p *SOCKS5Proxy) SetupNetworkJobs(ctx context.Context) (string, error) {
	if err := server.SetupSystemProxy(
		ctx,
		p.logger,
		"SOCKS5 "+server.PACProxyHostPort(p.listenAddr),
		StateFile,
	); err != nil {
		return "", err
	}
	return StateFile, nil
}

func (p *SOCKS5Proxy) Addr() string {
	return p.listenAddr.String()
}

func (p *SOCKS5Proxy) ActiveConns() int64 {
	return p.conns.Active()
}

func (p *SOCKS5Proxy) handleConnection(ctx context.Context, conn net.Conn) {
	logger := logging.WithLocalScope(ctx, p.logger, "socks5")

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer netutil.CloseConns(conn)

	// A client that sends nothing, or speaks another protocol, would
	// otherwise hold the connection until it gives up.
	if p.requestTimeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(p.requestTimeout))
	}

	// 1. Negotiation Phase
	if err := p.negotiate(logger, conn); err != nil {
		logger.Debug().Err(err).Msg("negotiation failed")
		return
	}

	// 2. Request Phase
	req, err := proto.ReadSocks5Request(conn)
	if err != nil {
		// The server closes conn and cancels ctx when it shuts down.
		shutdown := ctx.Err() != nil || errors.Is(err, net.ErrClosed)
		switch {
		case err == io.EOF || shutdown:
		case errors.Is(err, os.ErrDeadlineExceeded):
			logger.Debug().Err(err).Msg("no request in time")
		default:
			logger.Warn().Err(err).Msg("failed to read request")
		}
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	logger.Debug().
		Uint8("cmd", req.Cmd).
		Int("port", req.Port).
		Str("fqdn", req.FQDN).
		Str("ip", req.IP.String()).
		Msg("new request")

	switch req.Cmd {
	case proto.SOCKS5CmdConnect:
		if err = p.connectHandler.Handle(ctx, conn, req); err != nil {
			return // Handler logs error
		}

	case proto.SOCKS5CmdBind:
		// Bind command usually implies user wants the server to listen.
		// Destination address in request is usually zero or the IP of the client,
		// but SOCKS5 spec says "DST.ADDR and DST.PORT fields of the BIND request contains
		// the address and port of the party the client expects to connect to the application server."
		// For our basic BindHandler, we might not strictly validate this yet.
		if err = p.bindHandler.Handle(ctx, conn, req); err != nil {
			return
		}

	case proto.SOCKS5CmdUDPAssociate:
		// UDP Associate usually doesn't have destination info in the request
		if err = p.udpAssociateHandler.Handle(ctx, conn, req); err != nil {
			logger.Error().Err(err).Msg("failed to handle udp_associate")
			return
		}
	default:
		err = proto.SOCKS5CommandNotSupportedResponse().Write(conn)
		logger.Warn().Uint8("cmd", req.Cmd).Msg("unsupported command")
	}

	if err == nil {
		return
	}

	logger.Error().Err(err).Msg("failed to handle")
}

func (p *SOCKS5Proxy) negotiate(logger zerolog.Logger, conn net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}

	if header[0] != proto.SOCKSVersion {
		// Check if the first byte is 'C'(67), and the second byte is 'O'(79)
		// indicating a potential HTTP CONNECT method
		if len(header) > 1 && header[0] == 67 && header[1] == 79 {
			// Reconstruct the stream using the already read header and the remaining connection
			// This allows http.ReadRequest to parse the full request line including the method
			mr := io.MultiReader(bytes.NewReader(header), conn)
			bufReader := bufio.NewReader(mr)

			// Parse the HTTP request headers without waiting for EOF
			// ReadRequest reads only the header section and stops
			req, err := http.ReadRequest(bufReader)
			if err != nil {
				return fmt.Errorf("invalid request(unknown): %w", err)
			}

			// req.Host contains the target domain (e.g., "google.com:443")
			return fmt.Errorf("invalid request: http connect to %s", req.Host)
		}

		return fmt.Errorf("invalid version: %d", header[0])
	}

	nMethods := int(header[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	// Respond: Version 5, Method NoAuth(0)
	_, err := conn.Write([]byte{proto.SOCKSVersion, proto.SOCKS5AuthNone})
	return err
}
