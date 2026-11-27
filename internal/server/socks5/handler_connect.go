package socks5

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/desync"
	"github.com/xvzc/spoofdpi/internal/dns"
	"github.com/xvzc/spoofdpi/internal/logging"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/proto"
	"github.com/xvzc/spoofdpi/internal/rule"
	"github.com/xvzc/spoofdpi/internal/server"
)

type ConnectHandler struct {
	logger     zerolog.Logger
	desyncer   *desync.TLSDesyncer
	alerts     *server.TLSAlertWatcher
	resolver   dns.Resolver
	ruleSet    *rule.RuleSet
	listenAddr net.TCPAddr
	cfg        *config.RuntimeConfig
}

func NewConnectHandler(
	logger zerolog.Logger,
	desyncer *desync.TLSDesyncer,
	alerts *server.TLSAlertWatcher,
	resolver dns.Resolver,
	ruleSet *rule.RuleSet,
	listenAddr net.TCPAddr,
	cfg *config.RuntimeConfig,
) *ConnectHandler {
	return &ConnectHandler{
		logger:     logger,
		desyncer:   desyncer,
		alerts:     alerts,
		resolver:   resolver,
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
	c := &connectConn{h: h, conn: lConn, req: req}
	return c.serve(ctx)
}

// connectConn is one CONNECT request. It owns the remote connection it dials
// and closes it when serve returns.
type connectConn struct {
	h      *ConnectHandler
	conn   net.Conn
	req    *proto.SOCKS5Request
	logger zerolog.Logger

	dst     *netutil.Destination
	matched *config.Rule
	cfg     *config.RuntimeConfig
	rConn   net.Conn
	// inspectReply checks the server's first reply for a TLS alert. It is
	// nil unless a Client Hello went to the server.
	inspectReply func(first []byte)
}

func (c *connectConn) serve(ctx context.Context) error {
	c.logger = logging.WithLocalScope(ctx, c.h.logger, "connect")

	if err := c.resolveDestination(ctx); err != nil || c.dst == nil {
		return err
	}

	if err := c.checkDestination(); err != nil {
		return err
	}

	if err := c.dial(ctx); err != nil {
		return err
	}
	defer netutil.CloseConns(c.rConn)

	if err := c.reply(); err != nil {
		return err
	}

	c.logger.Debug().
		Str("local", c.rConn.LocalAddr().String()).
		Str("remote", c.rConn.RemoteAddr().String()).
		Msg("new remote conn")

	bufConn := netutil.NewBufferedConn(c.conn)
	proceed, err := c.forwardFirstMessage(ctx, bufConn)
	if err != nil || !proceed {
		return err
	}

	return c.tunnel(ctx, bufConn)
}

// checkDestination refuses a destination that is not valid, that the
// selected rule blocks, that has no IPv4 address while the rule sets
// ipv6 = false, or that is a link-local address without a zone, and writes
// the failure reply for it. Under a rule that sets ipv6 = false, it drops
// the IPv6 addresses of the destination.
func (c *connectConn) checkDestination() error {
	ok, err := c.dst.IsValid(&c.h.listenAddr)
	if err != nil {
		c.logger.Debug().Err(err).Msg("error determining if valid destination")
		if !ok {
			_ = proto.SOCKS5FailureResponse().Write(c.conn)
			return err
		}
	}

	if c.matched != nil && c.matched.Block {
		c.logger.Debug().Msg("request is blocked by policy")
		_ = proto.SOCKS5FailureResponse().Write(c.conn)
		return netutil.ErrBlocked
	}

	addrs, err := server.AllowedAddrs(c.matched, c.dst.Addrs)
	if err != nil {
		c.logger.Info().
			Str("dst", c.dst.String()).
			Err(err).
			Msg("request is refused by policy")
		_ = proto.SOCKS5NotAllowedResponse().Write(c.conn)
		return err
	}
	c.dst.Addrs = addrs

	// A link-local address is reachable only through the interface its zone
	// names, and a SOCKS5 address has no zone; only a literal sent as a
	// name can carry one.
	if c.dst.Zone == "" && len(c.dst.Addrs) == 1 && netutil.NeedsZone(c.dst.Addrs[0]) {
		_ = proto.SOCKS5AddrNotSupportedResponse().Write(c.conn)
		return fmt.Errorf("link-local address %s has no zone", c.dst.Addrs[0])
	}

	return nil
}

// dial connects to the destination, and writes the failure reply when it
// can't.
func (c *connectConn) dial(ctx context.Context) error {
	c.h.desyncer.PrepareHopTrack(c.dst.Addrs, &c.cfg.HTTPS)

	rConn, err := netutil.DialFastest(
		ctx, c.dst, "tcp", netutil.DialOptions{
			Timeout: c.cfg.Conn.TCPTimeout,
			Control: netutil.NoAutoFlowLabelControl(c.logger),
		},
	)
	if err != nil {
		_ = proto.SOCKS5FailureResponse().Write(c.conn)
		return err
	}
	c.rConn = rConn

	return nil
}

func (c *connectConn) reply() error {
	if err := proto.SOCKS5SuccessResponse().
		Bind(net.IPv4zero).
		Port(0).
		Write(c.conn); err != nil {
		c.logger.Error().Err(err).Msg("failed to write socks5 success reply")
		return err
	}

	return nil
}

// forwardFirstMessage sends the client's first TLS message to the remote,
// desynced when it is a ClientHello. It does nothing when the client
// doesn't start with a TLS handshake. It reports false, without an error,
// when the client closes before sending a whole message.
func (c *connectConn) forwardFirstMessage(
	ctx context.Context,
	bufConn *netutil.BufferedConn,
) (bool, error) {
	b, err := bufConn.Peek(1)
	if err != nil || b[0] != byte(proto.TLSHandshake) {
		c.logger.Debug().Msg("not a tls handshake. fallback to pure tcp")
		return true, nil
	}

	tlsMsg, err := proto.ReadTLSMessage(bufConn)
	if err != nil {
		if err == io.EOF || err.Error() == "unexpected EOF" {
			return false, nil
		}
		c.logger.Trace().Err(err).Msgf("failed to read first message from client")
		return false, err
	}

	if !tlsMsg.IsClientHello() {
		c.logger.Debug().
			Int("len", tlsMsg.Len()).
			Msg("not a client hello. fallback to pure tcp")
		if _, err := c.rConn.Write(tlsMsg.Raw()); err != nil {
			return false, fmt.Errorf("failed to write initial bytes to remote: %w", err)
		}
		return true, nil
	}

	c.inspectReply = c.h.alerts.Inspector(
		c.logger, c.rConn, server.SNI(tlsMsg), c.req.FQDN,
	)
	c.logger.Debug().
		Int("len", tlsMsg.Len()).
		Msgf("client hello received <- %s", c.conn.RemoteAddr())
	var n int
	if c.cfg.HTTPS.Skip {
		n, err = c.rConn.Write(tlsMsg.Raw())
	} else {
		n, err = c.h.desyncer.Desync(ctx, c.rConn, tlsMsg, &c.cfg.HTTPS, &c.cfg.Conn)
	}
	if err != nil {
		return false, fmt.Errorf("failed to send client hello: %w", err)
	}
	c.logger.Debug().Int("len", n).Msgf("sent client hello -> %s", c.rConn.RemoteAddr())

	return true, nil
}

func (c *connectConn) tunnel(ctx context.Context, bufConn *netutil.BufferedConn) error {
	return netutil.RelayBidirectional(
		ctx,
		c.logger,
		bufConn,
		c.rConn,
		netutil.RelayOptions{
			OnFirstReply: c.inspectReply,
		},
	)
}

// resolveDestination resolves the request's destination and selects its
// rule with server.SelectRule. A domain name is resolved with the DNS
// options of the domain rule it matches, else with the base ones. An IP
// literal sent as a name is not looked up, and its zone, if any, is the
// zone of the destination. It sets
// the destination, the selected rule (nil when none matches) and the config
// to apply. It leaves the destination nil, without an error, when the
// request names no address to connect to.
func (c *connectConn) resolveDestination(ctx context.Context) error {
	h, req, logger := c.h, c.req, c.logger

	var addrs []net.IP
	var zone string
	var nameRule *config.Rule

	if req.IP != nil {
		addrs = []net.IP{req.IP}
	} else if req.ATYP == proto.SOCKS5AddrTypeFQDN && len(req.FQDN) > 1 {
		name := req.FQDN
		if ip, err := netip.ParseAddr(name); err == nil {
			addrs = []net.IP{ip.AsSlice()}
			zone = ip.Zone()
		} else {
			// Matching the name alone gives the DNS options to resolve it with.
			var nameCfg *config.RuntimeConfig
			nameRule, nameCfg = server.SelectRule(h.ruleSet, h.cfg, name, nil)
			resolved, err := h.resolver.Resolve(ctx, &nameCfg.DNS, name)
			if err != nil {
				logger.Error().Str("domain", req.FQDN).Err(err).Msgf("dns lookup failed")
				_ = proto.SOCKS5HostUnreachableResponse().Write(c.conn)
				return err
			}
			addrs = netutil.IPsFromAddrs(resolved)
		}
	} else {
		logger.Trace().Msg("no addrs specified for this request. skipping")
		return nil
	}

	c.matched, c.cfg = server.SelectRule(
		h.ruleSet,
		h.cfg,
		"",
		addrs,
		nameRule,
	)

	if c.matched != nil && logger.GetLevel() == zerolog.TraceLevel {
		logger.Trace().RawJSON("summary", c.matched.JSON()).Msg("match")
	}

	c.dst = &netutil.Destination{
		Host:  req.FQDN,
		Addrs: addrs,
		Zone:  zone,
		Port:  req.Port,
	}
	return nil
}
