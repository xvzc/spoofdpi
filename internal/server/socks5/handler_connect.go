package socks5

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/desync"
	"github.com/xvzc/spoofdpi/internal/dns"
	"github.com/xvzc/spoofdpi/internal/logging"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/proto"
	"github.com/xvzc/spoofdpi/internal/rule"
)

type ConnectHandler struct {
	logger     zerolog.Logger
	desyncer   *desync.TLSDesyncer
	dns        *dns.Client
	ruleSet    *rule.RuleSet
	listenAddr net.TCPAddr
	cfg        *config.RuntimeConfig
}

func NewConnectHandler(
	logger zerolog.Logger,
	desyncer *desync.TLSDesyncer,
	dnsClient *dns.Client,
	ruleSet *rule.RuleSet,
	listenAddr net.TCPAddr,
	cfg *config.RuntimeConfig,
) *ConnectHandler {
	return &ConnectHandler{
		logger:     logger,
		desyncer:   desyncer,
		dns:        dnsClient,
		ruleSet:    ruleSet,
		listenAddr: listenAddr,
		cfg:        cfg,
	}
}

func (h *ConnectHandler) Handle(
	ctx context.Context,
	lConn net.Conn,
	req *proto.SOCKS5Request,
) error {
	logger := logging.WithLocalScope(ctx, h.logger, "connect")

	dst, matched, err := h.resolveDestination(ctx, logger, req)
	if err != nil || dst == nil {
		return err
	}

	cfg := h.cfg
	if matched != nil {
		cfg = &matched.Config
	}

	// 1. Validate destination
	ok, err := dst.IsValid(&h.listenAddr)
	if err != nil {
		logger.Debug().Err(err).Msg("error determining if valid destination")
		if !ok {
			_ = proto.SOCKS5FailureResponse().Write(lConn)
			return err
		}
	}

	// 2. Check if blocked
	if matched != nil && matched.Block {
		logger.Debug().Msg("request is blocked by policy")
		_ = proto.SOCKS5FailureResponse().Write(lConn)
		return netutil.ErrBlocked
	}

	// 3. Dial remote
	h.desyncer.PrepareHopTrack(dst.Addrs, &cfg.HTTPS)

	rConn, err := netutil.DialFastest(ctx, dst, "tcp", cfg.Conn.TCPTimeout, nil)
	if err != nil {
		_ = proto.SOCKS5FailureResponse().Write(lConn)
		return err
	}
	defer netutil.CloseConns(rConn)

	// 4. Send success response
	if err := proto.SOCKS5SuccessResponse().
		Bind(net.IPv4zero).
		Port(0).
		Write(lConn); err != nil {
		logger.Error().Err(err).Msg("failed to write socks5 success reply")
		return err
	}

	logger.Debug().Msgf("new remote conn -> %s", rConn.RemoteAddr())

	// 5. Peek for TLS
	bufConn := netutil.NewBufferedConn(lConn)
	b, err := bufConn.Peek(1)

	if err == nil && b[0] == byte(proto.TLSHandshake) {
		// 6. Read ClientHello
		tlsMsg, err := proto.ReadTLSMessage(bufConn)
		if err != nil {
			if err == io.EOF || err.Error() == "unexpected EOF" {
				return nil
			}
			logger.Trace().Err(err).Msgf("failed to read first message from client")
			return err
		}

		if tlsMsg.IsClientHello() {
			// 7. Send ClientHello with desync
			logger.Debug().
				Int("len", tlsMsg.Len()).
				Msgf("client hello received <- %s", lConn.RemoteAddr())
			var n int
			if cfg.HTTPS.Skip {
				n, err = rConn.Write(tlsMsg.Raw())
			} else {
				n, err = h.desyncer.Desync(ctx, rConn, tlsMsg, &cfg.HTTPS, &cfg.Conn)
			}
			if err != nil {
				return fmt.Errorf("failed to send client hello: %w", err)
			}
			logger.Debug().Int("len", n).Msgf("sent client hello -> %s", rConn.RemoteAddr())
		} else {
			logger.Debug().
				Int("len", tlsMsg.Len()).
				Msg("not a client hello. fallback to pure tcp")
			if _, err := rConn.Write(tlsMsg.Raw()); err != nil {
				return fmt.Errorf("failed to write initial bytes to remote: %w", err)
			}
		}
	} else {
		logger.Debug().Msg("not a tls handshake. fallback to pure tcp")
	}

	// 8. Tunnel
	resCh := make(chan netutil.TransferResult, 2)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	startedAt := time.Now()
	go netutil.TunnelConns(ctx, resCh, rConn, bufConn, netutil.TunnelDirOut)
	go netutil.TunnelConns(ctx, resCh, bufConn, rConn, netutil.TunnelDirIn)

	return netutil.WaitForTunnelCompletion(
		ctx,
		logger,
		resCh,
		startedAt,
		netutil.DescribeRoute(bufConn, rConn),
		nil,
	)
}

// resolveDestination resolves the request's destination and selects its
// rule: the domain name is matched first and resolved with that rule's DNS
// options (the base options when nothing matches), then the addresses are
// matched; the higher-priority match wins, the address on a tie. It
// returns a nil destination, without an error, when the request names no
// address to connect to.
func (h *ConnectHandler) resolveDestination(
	ctx context.Context,
	logger zerolog.Logger,
	req *proto.SOCKS5Request,
) (*netutil.Destination, *config.Rule, error) {
	var addrs []net.IP
	var nameMatch *config.Rule

	if req.IP != nil {
		addrs = []net.IP{req.IP}
	} else if req.ATYP == proto.SOCKS5AddrTypeFQDN && len(req.FQDN) > 1 {
		nameMatch = h.ruleSet.Search([]rule.Query{
			{Type: rule.MatchTypeDomain, Value: req.FQDN},
		})

		dnsOpts := &h.cfg.DNS
		if nameMatch != nil {
			dnsOpts = &nameMatch.Config.DNS
		}

		// Resolve Domain
		netAddrs, err := h.dns.Resolve(ctx, dnsOpts, req.FQDN)
		if err != nil {
			logger.Error().Str("domain", req.FQDN).Err(err).Msgf("dns lookup failed")
			return nil, nil, err
		}

		addrs = make([]net.IP, len(netAddrs))
		for i, a := range netAddrs {
			addrs[i] = a.AsSlice()
		}
	} else {
		logger.Trace().Msg("no addrs specified for this request. skipping")
		return nil, nil, nil
	}

	var addrQueries []rule.Query
	for _, v := range addrs {
		addrQueries = append(
			addrQueries,
			rule.Query{Type: rule.MatchTypeAddr, Value: v.String()},
		)
	}

	addrMatch := h.ruleSet.Search(addrQueries)

	bestMatch := rule.HigherPriority(addrMatch, nameMatch)
	if bestMatch != nil && logger.GetLevel() == zerolog.TraceLevel {
		logger.Trace().RawJSON("summary", bestMatch.JSON()).Msg("match")
	}

	dst := &netutil.Destination{
		Host:  req.FQDN,
		Addrs: addrs,
		Port:  req.Port,
	}
	return dst, bestMatch, nil
}
