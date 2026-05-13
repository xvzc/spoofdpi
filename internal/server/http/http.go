package http

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/dns"
	"github.com/xvzc/spoofdpi/internal/logging"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/packet"
	"github.com/xvzc/spoofdpi/internal/proto"
	"github.com/xvzc/spoofdpi/internal/rule"
	"github.com/xvzc/spoofdpi/internal/server"
	"github.com/xvzc/spoofdpi/internal/session"
)

// HTTPSystemNetwork handles OS-specific network configuration for HTTP proxy.
type HTTPSystemNetwork interface {
	DefaultRoute() *packet.Route
	BuildJobs(port uint16, pacURL string) ([]netutil.NetworkJob, error)
}

type HTTPProxy struct {
	logger zerolog.Logger

	dns          *dns.Client
	httpHandler  *HTTPHandler
	httpsHandler *HTTPSHandler
	ruleSet      *rule.RuleSet

	tcpSniffer packet.Sniffer
	sysNet     HTTPSystemNetwork
	listenAddr net.TCPAddr
	cfg        *config.RuntimeConfig
}

func NewHTTPProxy(
	logger zerolog.Logger,
	dnsClient *dns.Client,
	httpHandler *HTTPHandler,
	httpsHandler *HTTPSHandler,
	ruleSet *rule.RuleSet,
	tcpSniffer packet.Sniffer,
	sysNet HTTPSystemNetwork,
	listenAddr net.TCPAddr,
	cfg *config.RuntimeConfig,
) server.Server {
	return &HTTPProxy{
		logger:       logger,
		dns:          dnsClient,
		httpHandler:  httpHandler,
		httpsHandler: httpsHandler,
		ruleSet:      ruleSet,
		tcpSniffer:   tcpSniffer,
		sysNet:       sysNet,
		listenAddr:   listenAddr,
		cfg:          cfg,
	}
}

func (p *HTTPProxy) ListenAndServe(
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
					return
				}

				p.logger.Error().Err(err).Msgf("failed to accept new connection")
				delay = server.BackoffOnError(delay)

				continue
			}

			go p.handleNewConnection(session.WithNewTraceID(context.Background()), conn)
		}
	}()

	return nil
}

func (p *HTTPProxy) SetupNetworkJobs(ctx context.Context) (string, error) {
	pacContent := fmt.Sprintf(
		"function FindProxyForURL(url, host) {\n    return \"PROXY 127.0.0.1:%d; DIRECT\";\n}",
		p.listenAddr.Port,
	)
	pacURL, pac, err := netutil.RunPACServer(pacContent)
	if err != nil {
		return "", fmt.Errorf("error creating pac server: %w", err)
	}
	jobs, err := p.sysNet.BuildJobs(uint16(p.listenAddr.Port), pacURL)
	if err != nil {
		_ = pac.Close()
		return "", err
	}
	if err := netutil.SaveJobs(StateFile, jobs); err != nil {
		_ = pac.Close()
		return "", fmt.Errorf("failed to save state: %w", err)
	}
	go func() { <-ctx.Done(); _ = pac.Close() }()
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
		if err != io.EOF {
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

	host := req.ExtractHost()
	dstPort, err := req.ExtractPort()
	if err != nil {
		logger.Warn().Str("host", req.Host).Msg("failed to extract port")
		_ = proto.HTTPBadRequestResponse().Write(conn)

		return
	}

	logger.Debug().
		Str("method", req.Method).
		Str("from", conn.RemoteAddr().String()).
		Msg("new request")

	var addrs []net.IP
	var nameMatch *config.Rule
	if net.ParseIP(host) != nil {
		addrs = []net.IP{net.ParseIP(host)}
		logger.Trace().Msgf("skipping dns lookup for non-domain host %q", host)
	} else {
		nameMatch = p.ruleSet.Search([]rule.Query{
			{Type: rule.MatchTypeDomain, Value: host},
		})

		netAddrs, err := p.dns.Resolve(ctx, nameMatch, host)
		if err != nil {
			_ = proto.HTTPBadGatewayResponse().Write(conn)
			logger.Error().Err(err).Msgf("dns lookup failed for %s", host)

			return
		}

		addrs = make([]net.IP, len(netAddrs))
		for i, a := range netAddrs {
			addrs[i] = a.AsSlice()
		}
	}

	dst := &netutil.Destination{
		Host:  host,
		Addrs: addrs,
		Port:  dstPort,
	}

	// Avoid recursively querying self.
	ok, err := dst.IsValid(&p.listenAddr)
	if err != nil {
		logger.Debug().Err(err).Msg("error validating dst addrs")
		if !ok {
			_ = proto.HTTPForbiddenResponse().Write(conn)
		}
	}

	var addrQueries []rule.Query
	for _, v := range addrs {
		addrQueries = append(
			addrQueries,
			rule.Query{Type: rule.MatchTypeAddr, Value: v.String()},
		)
	}

	addrMatch := p.ruleSet.Search(addrQueries)

	bestMatch := rule.HigherPriority(addrMatch, nameMatch)
	if bestMatch != nil && logger.GetLevel() == zerolog.TraceLevel {
		logger.Trace().RawJSON("summary", bestMatch.JSON()).Msg("match")
	}

	if bestMatch != nil && bestMatch.Block {
		logger.Debug().Msg("request is blocked by policy")
		return
	}

	var handleErr error
	if req.IsConnectMethod() {
		handleErr = p.httpsHandler.HandleRequest(ctx, conn, dst, bestMatch)
	} else {
		handleErr = p.httpHandler.HandleRequest(ctx, conn, req, dst, bestMatch)
	}

	if handleErr == nil { // Early exit if no error found
		return
	}

	logger.Warn().Err(handleErr).Msg("error handling request")
}
