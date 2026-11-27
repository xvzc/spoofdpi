package http

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"

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

type HTTPSHandler struct {
	logger     zerolog.Logger
	desyncer   *desync.TLSDesyncer
	alerts     *server.TLSAlertWatcher
	resolver   dns.Resolver
	ruleSet    *rule.RuleSet
	listenAddr net.TCPAddr
	cfg        *config.RuntimeConfig
}

func NewHTTPSHandler(
	logger zerolog.Logger,
	desyncer *desync.TLSDesyncer,
	alerts *server.TLSAlertWatcher,
	resolver dns.Resolver,
	ruleSet *rule.RuleSet,
	listenAddr net.TCPAddr,
	cfg *config.RuntimeConfig,
) *HTTPSHandler {
	return &HTTPSHandler{
		logger:     logger,
		desyncer:   desyncer,
		alerts:     alerts,
		resolver:   resolver,
		ruleSet:    ruleSet,
		listenAddr: listenAddr,
		cfg:        cfg,
	}
}

// Handle serves one CONNECT request read from lConn.
func (h *HTTPSHandler) Handle(
	ctx context.Context,
	lConn net.Conn,
	req *proto.HTTPRequest,
) error {
	c := &httpsConn{h: h, conn: lConn, req: req}
	return c.serve(ctx)
}

// httpsConn is one CONNECT request. It owns the remote connection it dials
// and closes it when serve returns.
type httpsConn struct {
	h      *HTTPSHandler
	conn   net.Conn
	req    *proto.HTTPRequest
	logger zerolog.Logger

	dst     *netutil.Destination
	matched *config.Rule
	cfg     *config.RuntimeConfig
	rConn   net.Conn
	sni     string
}

func (c *httpsConn) serve(ctx context.Context) error {
	c.logger = logging.WithLocalScope(ctx, c.h.logger, "https")

	if !c.selectDestination(ctx) || !c.checkDestination() {
		return nil
	}

	c.h.desyncer.PrepareHopTrack(c.dst.Addrs, &c.cfg.HTTPS)

	proceed, err := c.reply()
	if err != nil || !proceed {
		return err
	}

	if err := c.dial(ctx); err != nil {
		return err
	}
	defer netutil.CloseConns(c.rConn)

	c.logger.Debug().
		Str("local", c.rConn.LocalAddr().String()).
		Str("remote", c.rConn.RemoteAddr().String()).
		Msg("new remote conn")

	proceed, err = c.desync(ctx)
	if err != nil || !proceed {
		return err
	}

	return c.tunnel(ctx)
}

// selectDestination resolves the request's destination and selects its
// rule. It writes the failure reply and reports false when the request
// names no usable destination.
func (c *httpsConn) selectDestination(ctx context.Context) bool {
	host := c.req.ExtractHost()
	port, err := c.req.ExtractPort()
	if err != nil {
		c.logger.Warn().Str("host", c.req.Host).Msg("failed to extract port")
		_ = proto.HTTPBadRequestResponse().Write(c.conn)
		return false
	}

	c.dst, c.matched, c.cfg, err = resolveDestination(
		ctx, c.logger, c.h.resolver, c.h.ruleSet, c.h.cfg, host, port,
	)
	if err != nil {
		_ = proto.HTTPBadGatewayResponse().Write(c.conn)
		c.logger.Error().Err(err).Msgf("dns lookup failed for %s", host)
		return false
	}

	return true
}

// checkDestination writes a 403 for a destination that is the proxy itself,
// and a 502 for one that the rule's ipv6 = false leaves no address of. It
// reports false when the request must not go on.
func (c *httpsConn) checkDestination() bool {
	switch verifyDestination(c.logger, c.dst, c.matched, &c.h.listenAddr) {
	case destinationSelf:
		_ = proto.HTTPForbiddenResponse().Write(c.conn)
		return false
	case destinationBlocked:
		return false
	case destinationIPv4Only:
		_ = proto.HTTPBadGatewayResponse().Write(c.conn)
		return false
	default:
		return true
	}
}

// reply sends 200 Connection Established. It reports false, without an
// error, when the client has gone away.
func (c *httpsConn) reply() (bool, error) {
	if err := proto.HTTPConnectionEstablishedResponse().Write(c.conn); err != nil {
		if !netutil.IsConnectionResetByPeer(err) && !errors.Is(err, io.EOF) {
			c.logger.Trace().Err(err).Msgf("proxy handshake error")
			return false, fmt.Errorf("failed to handle proxy handshake: %w", err)
		}
		return false, nil
	}
	c.logger.Trace().Msgf("sent 200 connection established -> %s", c.conn.RemoteAddr())

	return true, nil
}

func (c *httpsConn) dial(ctx context.Context) error {
	rConn, err := netutil.DialFastest(
		ctx, c.dst, "tcp", netutil.DialOptions{
			Timeout: c.cfg.Conn.TCPTimeout,
			Control: netutil.NoAutoFlowLabelControl(c.logger),
		},
	)
	if err != nil {
		return err
	}
	c.rConn = rConn

	return nil
}

// desync reads the client's ClientHello and sends it to the remote with
// desync. It reports false, without an error, when the client closes before
// sending a whole message or doesn't start with a ClientHello.
func (c *httpsConn) desync(ctx context.Context) (bool, error) {
	tlsMsg, err := proto.ReadTLSMessage(c.conn)
	if err != nil {
		if err == io.EOF || err.Error() == "unexpected EOF" {
			return false, nil
		}
		c.logger.Trace().Err(err).Msgf("failed to read first message from client")
		return false, err
	}

	c.logger.Debug().
		Int("len", tlsMsg.Len()).
		Msgf("client hello received <- %s", c.conn.RemoteAddr())

	if !tlsMsg.IsClientHello() {
		c.logger.Trace().Int("len", tlsMsg.Len()).Msg("not a client hello. aborting")
		return false, nil
	}

	c.sni = server.SNI(tlsMsg)

	n, err := c.h.desyncer.Desync(ctx, c.rConn, tlsMsg, &c.cfg.HTTPS, &c.cfg.Conn)
	if err != nil {
		return false, fmt.Errorf("failed to send client hello: %w", err)
	}

	c.logger.Debug().Int("len", n).Msgf("sent client hello -> %s", c.rConn.RemoteAddr())

	return true, nil
}

func (c *httpsConn) tunnel(ctx context.Context) error {
	inspectReply := c.h.alerts.Inspector(c.logger, c.rConn, c.sni, c.req.ExtractHost())

	handleErrs := func(errs []error) error {
		if len(errs) == 0 {
			return nil
		}
		if slices.ContainsFunc(errs, netutil.IsConnectionResetByPeer) {
			return netutil.ErrBlocked
		}
		return errs[0]
	}

	return netutil.RelayBidirectional(
		ctx,
		c.logger,
		c.conn,
		c.rConn,
		netutil.RelayOptions{
			OnFirstReply: inspectReply,
			HandleErrs:   handleErrs,
		},
	)
}
