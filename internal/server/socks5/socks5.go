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
	"github.com/samber/lo"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/dns"
	"github.com/xvzc/spoofdpi/internal/logging"
	"github.com/xvzc/spoofdpi/internal/matcher"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/packet"
	"github.com/xvzc/spoofdpi/internal/proto"
	"github.com/xvzc/spoofdpi/internal/server"
	"github.com/xvzc/spoofdpi/internal/session"
)

// SOCKS5SystemNetwork handles OS-specific network configuration for SOCKS5 proxy.
type SOCKS5SystemNetwork interface {
	DefaultRoute() *netutil.Route
}

type SOCKS5Proxy struct {
	logger zerolog.Logger

	resolver            dns.Resolver
	ruleMatcher         matcher.RuleMatcher
	connectHandler      *ConnectHandler
	bindHandler         *BindHandler
	udpAssociateHandler *UdpAssociateHandler

	tcpSniffer packet.Sniffer
	udpSniffer packet.Sniffer
	sysNet     SOCKS5SystemNetwork
	listenAddr net.TCPAddr
	rt         *config.RuntimeConfig
}

func NewSOCKS5Proxy(
	logger zerolog.Logger,
	resolver dns.Resolver,
	ruleMatcher matcher.RuleMatcher,
	connectHandler *ConnectHandler,
	bindHandler *BindHandler,
	udpAssociateHandler *UdpAssociateHandler,
	tcpSniffer packet.Sniffer,
	udpSniffer packet.Sniffer,
	sysNet SOCKS5SystemNetwork,
	listenAddr net.TCPAddr,
	rt *config.RuntimeConfig,
) server.Server {
	return &SOCKS5Proxy{
		logger:              logger,
		resolver:            resolver,
		ruleMatcher:         ruleMatcher,
		connectHandler:      connectHandler,
		bindHandler:         bindHandler,
		udpAssociateHandler: udpAssociateHandler,
		tcpSniffer:          tcpSniffer,
		udpSniffer:          udpSniffer,
		sysNet:              sysNet,
		listenAddr:          listenAddr,
		rt:                  rt,
	}
}

func (p *SOCKS5Proxy) ListenAndServe(
	appctx context.Context,
) error {
	// Start pcap capture only if sniffers were supplied
	// (i.e., cfg.NeedsRawTCP() / NeedsRawUDP() was true at startup).
	if p.tcpSniffer != nil {
		p.tcpSniffer.StartCapturing()
	}
	if p.udpSniffer != nil {
		p.udpSniffer.StartCapturing()
	}

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

func (p *SOCKS5Proxy) AutoConfigureNetwork(ctx context.Context) (func(), error) {
	if p.sysNet == nil {
		return nil, fmt.Errorf("system network not initialized")
	}

	if staleState, exists, err := loadState(); err == nil && exists {
		p.logger.Info().Msg("cleaning up stale state")
		staleStateJobs := configurationJobs(ctx, p.logger, staleState)

		for i := len(staleStateJobs) - 1; i >= 0; i-- {
			if err := staleStateJobs[i].Reset(); err != nil {
				p.logger.Error().Err(err).Msg("failed to run unset job")
			}
		}

		if err := deleteState(); err != nil {
			p.logger.Error().Err(err).Msg("failed to delete stale state")
		}
	}

	pacContent := fmt.Sprintf(`function FindProxyForURL(url, host) {
    return "SOCKS5 127.0.0.1:%d; DIRECT";
}`, p.listenAddr.Port)

	pacURL, pacServer, err := netutil.RunPACServer(pacContent)
	if err != nil {
		return nil, fmt.Errorf("error creating pac server: %w", err)
	}

	newState, err := createState(
		p.sysNet.DefaultRoute(), uint16(p.listenAddr.Port), pacURL,
	)
	if err != nil {
		_ = pacServer.Close()
		return nil, err
	}

	if err := saveState(newState); err != nil {
		_ = pacServer.Close()
		return nil, fmt.Errorf("failed to save state: %w", err)
	}

	newStateJobs := configurationJobs(ctx, p.logger, newState)
	var executedJobs int

	set := func() error {
		for i, each := range newStateJobs {
			if each.Apply == nil {
				continue
			}

			if err := each.Apply(); err != nil {
				return fmt.Errorf("failed to run set job: %w", err)
			}
			executedJobs = i + 1
		}
		return nil
	}

	unset := func() {
		for i := executedJobs - 1; i >= 0; i-- {
			if newStateJobs[i].Reset == nil {
				continue
			}

			if err := newStateJobs[i].Reset(); err != nil {
				p.logger.Error().Err(err).Msg("failed to run unset job")
			}
		}

		_ = pacServer.Close()

		if err := deleteState(); err != nil {
			p.logger.Error().Err(err).Msg("failed to delete state file during cleanup")
		}
	}

	if err := set(); err != nil {
		unset()
		return nil, err
	}

	return unset, nil
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

	logger.Trace().
		Uint8("cmd", req.Cmd).
		Int("port", req.Port).
		Str("fqdn", req.FQDN).
		Str("ip", req.IP.String()).
		Msg("new request")

	var addrs []net.IP
	var nameMatch *config.Rule

	if req.IP != nil {
		addrs = []net.IP{req.IP}
	} else if req.ATYP == proto.SOCKS5AddrTypeFQDN && len(req.FQDN) > 1 {
		nameMatch = p.ruleMatcher.Search(
			&matcher.Selector{
				Kind:   matcher.MatchKindDomain,
				Domain: lo.ToPtr(req.FQDN), // req.Domain -> req.FQDN
			},
		)

		// Resolve Domain
		rSet, err := p.resolver.Resolve(ctx, req.FQDN, nil, nameMatch)
		if err != nil {
			logger.Error().Str("domain", req.FQDN).Err(err).Msgf("dns lookup failed")
			return
		}

		addrs = rSet.Addrs
	} else {
		logger.Trace().Msg("no addrs specified for this request. skipping")
	}

	var selectors []*matcher.Selector
	for _, v := range addrs {
		selectors = append(selectors, &matcher.Selector{
			Kind: matcher.MatchKindAddr,
			IP:   lo.ToPtr(v),
			Port: lo.ToPtr(uint16(req.Port)),
		})
	}

	addrMatch := p.ruleMatcher.SearchAll(selectors)

	bestMatch := matcher.GetHigherPriorityRule(addrMatch, nameMatch)
	if bestMatch != nil && logger.GetLevel() == zerolog.TraceLevel {
		logger.Trace().RawJSON("summary", bestMatch.JSON()).Msg("match")
	}

	switch req.Cmd {
	case proto.SOCKS5CmdConnect:
		dst := &netutil.Destination{
			Domain: req.FQDN,
			Addrs:  addrs,
			Port:   req.Port,
		}
		if err = p.connectHandler.Handle(ctx, conn, req, dst, bestMatch); err != nil {
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
		if err = p.udpAssociateHandler.Handle(ctx, conn, req, nil, nil); err != nil {
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
