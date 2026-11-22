package http

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/dns"
	"github.com/xvzc/spoofdpi/internal/logging"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/proto"
	"github.com/xvzc/spoofdpi/internal/rule"
	"github.com/xvzc/spoofdpi/internal/server"
)

type HTTPProxy struct {
	logger zerolog.Logger

	httpHandler  *HTTPHandler
	httpsHandler *HTTPSHandler
	resolver     dns.Resolver
	ruleSet      *rule.RuleSet
	listenAddr   net.TCPAddr
	cfg          *config.RuntimeConfig

	listener *net.TCPListener
	conns    server.ConnTracker
}

func NewHTTPProxy(
	logger zerolog.Logger,
	httpHandler *HTTPHandler,
	httpsHandler *HTTPSHandler,
	resolver dns.Resolver,
	ruleSet *rule.RuleSet,
	listenAddr net.TCPAddr,
	cfg *config.RuntimeConfig,
) server.Server {
	return &HTTPProxy{
		logger:       logger,
		httpHandler:  httpHandler,
		httpsHandler: httpsHandler,
		resolver:     resolver,
		ruleSet:      ruleSet,
		listenAddr:   listenAddr,
		cfg:          cfg,
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

	addrs, hostRule, err := p.resolveHost(ctx, logger, host)
	if err != nil {
		_ = proto.HTTPBadGatewayResponse().Write(conn)
		logger.Error().Err(err).Msgf("dns lookup failed for %s", host)

		return
	}

	matched, _ := server.SelectRule(p.ruleSet, p.cfg, "", addrs, hostRule)

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

	if matched != nil && logger.GetLevel() == zerolog.TraceLevel {
		logger.Trace().RawJSON("summary", matched.JSON()).Msg("match")
	}

	if matched != nil && matched.Block {
		logger.Debug().Msg("request is blocked by policy")
		return
	}

	var handleErr error
	if req.IsConnectMethod() {
		handleErr = p.httpsHandler.HandleRequest(ctx, conn, dst, matched)
	} else {
		handleErr = p.httpHandler.HandleRequest(ctx, conn, req, dst, matched)
	}

	if handleErr == nil { // Early exit if no error found
		return
	}

	logger.Warn().Err(handleErr).Msg("error handling request")
}

// resolveHost returns the addresses of host: host itself when it is an IP
// literal, else the addresses p.resolver resolves it to with the DNS options
// of the domain rule it matches, else with the base ones. It also returns
// that domain rule, nil for an IP literal or when none matches.
func (p *HTTPProxy) resolveHost(
	ctx context.Context,
	logger zerolog.Logger,
	host string,
) ([]net.IP, *config.Rule, error) {
	if ip := net.ParseIP(host); ip != nil {
		logger.Trace().Msgf("skipping dns lookup for non-domain host %q", host)
		return []net.IP{ip}, nil, nil
	}
	if host == "" {
		return nil, nil, errors.New("no host to look up")
	}

	// Matching the host alone gives the DNS options to resolve it with.
	hostRule, hostCfg := server.SelectRule(p.ruleSet, p.cfg, host, nil)
	resolved, err := p.resolver.Resolve(ctx, &hostCfg.DNS, host)
	if err != nil {
		return nil, nil, err
	}

	return netutil.IPsFromAddrs(resolved), hostRule, nil
}
