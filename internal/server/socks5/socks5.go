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
	"time"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/logging"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/proto"
	"github.com/xvzc/spoofdpi/internal/server"
	"github.com/xvzc/spoofdpi/internal/session"
)

type SOCKS5Proxy struct {
	logger zerolog.Logger

	connectHandler      *ConnectHandler
	bindHandler         *BindHandler
	udpAssociateHandler *UdpAssociateHandler
	listenAddr          net.TCPAddr
}

func NewSOCKS5Proxy(
	logger zerolog.Logger,
	connectHandler *ConnectHandler,
	bindHandler *BindHandler,
	udpAssociateHandler *UdpAssociateHandler,
	listenAddr net.TCPAddr,
) server.Server {
	return &SOCKS5Proxy{
		logger:              logger,
		connectHandler:      connectHandler,
		bindHandler:         bindHandler,
		udpAssociateHandler: udpAssociateHandler,
		listenAddr:          listenAddr,
	}
}

func (p *SOCKS5Proxy) ListenAndServe(
	appctx context.Context,
) error {
	listener, err := net.ListenTCP("tcp", &p.listenAddr)
	if err != nil {
		return fmt.Errorf(
			"error creating listener on %s: %w",
			p.listenAddr.String(),
			err,
		)
	}

	go func() {
		<-appctx.Done()
		_ = listener.Close()
	}()

	go func() {
		var delay time.Duration
		for {
			conn, err := listener.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return // Normal shutdown
				}

				p.logger.Error().Err(err).Msg("failed to accept new connection")
				server.BackoffOnError(delay)

				continue
			}

			go p.handleConnection(session.WithNewTraceID(appctx), conn)
		}
	}()

	return nil
}

func (p *SOCKS5Proxy) SetupNetworkJobs(ctx context.Context) (string, error) {
	if err := server.SetupSystemProxy(
		ctx,
		fmt.Sprintf("SOCKS5 127.0.0.1:%d", p.listenAddr.Port),
		StateFile,
	); err != nil {
		return "", err
	}
	return StateFile, nil
}

func (p *SOCKS5Proxy) Addr() string {
	return p.listenAddr.String()
}

func (p *SOCKS5Proxy) handleConnection(ctx context.Context, conn net.Conn) {
	logger := logging.WithLocalScope(ctx, p.logger, "socks5")

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer netutil.CloseConns(conn)

	// 1. Negotiation Phase
	if err := p.negotiate(logger, conn); err != nil {
		logger.Debug().Err(err).Msg("negotiation failed")
		return
	}

	// 2. Request Phase
	req, err := proto.ReadSocks5Request(conn)
	if err != nil {
		if err != io.EOF {
			logger.Warn().Err(err).Msg("failed to read request")
		}
		return
	}

	// ctx = session.WithHostInfo(ctx, req.Host())
	// logger = logger.With().Ctx(ctx).Logger()

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
