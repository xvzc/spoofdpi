package socks5

import (
	"container/list"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

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

// maxUDPFlows is how many remote flows one UDP association keeps open.
// Opening another closes the one used least recently.
const maxUDPFlows = 256

type UdpAssociateHandler struct {
	logger   zerolog.Logger
	desyncer *desync.UDPDesyncer
	ruleSet  *rule.RuleSet
	cfg      *config.RuntimeConfig

	// resolver resolves the destinations that clients send as domain names.
	resolver dns.Resolver
	// maxFlows is how many remote flows one association keeps open.
	maxFlows int
}

func NewUdpAssociateHandler(
	logger zerolog.Logger,
	desyncer *desync.UDPDesyncer,
	resolver dns.Resolver,
	ruleSet *rule.RuleSet,
	cfg *config.RuntimeConfig,
) *UdpAssociateHandler {
	return &UdpAssociateHandler{
		logger:   logger,
		desyncer: desyncer,
		ruleSet:  ruleSet,
		cfg:      cfg,

		resolver: resolver,
		maxFlows: maxUDPFlows,
	}
}

func (h *UdpAssociateHandler) Handle(
	ctx context.Context,
	lConn net.Conn,
	req *proto.SOCKS5Request,
) error {
	c := newUdpAssociateConn(h, lConn, req)
	return c.serve(ctx)
}

// udpAssociateConn is one UDP association. It owns the relay socket and the
// remote flows it opens, and closes them all when serve returns: "A UDP
// association terminates when the TCP connection that the UDP ASSOCIATE
// request arrived on terminates" (RFC 1928, section 6).
type udpAssociateConn struct {
	h      *UdpAssociateHandler
	conn   net.Conn
	req    *proto.SOCKS5Request
	logger zerolog.Logger

	relay *net.UDPConn
	// controlDone is closed when the control connection ends.
	controlDone chan struct{}
	// wg tracks the goroutines serve starts.
	wg sync.WaitGroup

	mu sync.Mutex
	// flows holds the open flows by client address and destination.
	flows map[netutil.NATKey]*udpFlow
	// lru orders the flows from the most to the least recently used.
	lru *list.List
}

func newUdpAssociateConn(
	h *UdpAssociateHandler,
	conn net.Conn,
	req *proto.SOCKS5Request,
) *udpAssociateConn {
	return &udpAssociateConn{
		h:     h,
		conn:  conn,
		req:   req,
		flows: make(map[netutil.NATKey]*udpFlow),
		lru:   list.New(),
	}
}

// udpFlow is a connected socket to one destination, for one client address.
type udpFlow struct {
	key  netutil.NATKey
	conn *netutil.IdleTimeoutConn
	elem *list.Element
}

func (c *udpAssociateConn) serve(ctx context.Context) error {
	c.logger = logging.WithLocalScope(ctx, c.h.logger, "udp_associate")

	if err := c.listen(); err != nil {
		return err
	}
	defer c.release()

	// Reply with the bound address
	lUDPAddr := c.relay.LocalAddr().(*net.UDPAddr)
	err := proto.SOCKS5SuccessResponse().
		Bind(lUDPAddr.IP).
		Port(lUDPAddr.Port).
		Write(c.conn)
	if err != nil {
		c.logger.Error().Err(err).Msg("failed to write socks5 success reply")
		return err
	}

	c.watchControl()

	return c.relayOutbound(ctx)
}

// listen opens the relay socket on a random port, and writes the failure
// reply when it can't.
func (c *udpAssociateConn) listen() error {
	lTCPAddr := c.conn.LocalAddr().(*net.TCPAddr) // SOCKS5 listens on TCP
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: lTCPAddr.IP, Port: 0})
	if err != nil {
		c.logger.Error().Err(err).Msg("failed to create udp listener")
		_ = proto.SOCKS5FailureResponse().Write(c.conn)
		return err
	}
	c.relay = relay

	c.logger.Debug().
		Str("addr", relay.LocalAddr().String()).
		Str("network", relay.LocalAddr().Network()).
		Msg("new conn")

	c.logger.Debug().
		Str("bind_addr", relay.LocalAddr().String()).
		Msg("socks5 udp associate established")

	return nil
}

// watchControl closes the relay socket when the control connection ends,
// which ends relayOutbound.
func (c *udpAssociateConn) watchControl() {
	c.controlDone = make(chan struct{})
	c.wg.Go(func() {
		_, _ = io.Copy(io.Discard, c.conn) // Block until TCP closes
		close(c.controlDone)
		_ = c.relay.Close()
	})
}

// release closes the relay socket and every flow, and waits for the
// goroutines serve started to return.
func (c *udpAssociateConn) release() {
	_ = c.relay.Close()

	c.mu.Lock()
	for key, f := range c.flows {
		_ = f.conn.Close()
		delete(c.flows, key)
	}
	c.lru.Init()
	c.mu.Unlock()

	// Unblock watchControl if the control connection is still open.
	_ = c.conn.SetReadDeadline(time.Now())
	c.wg.Wait()
	_ = c.conn.SetReadDeadline(time.Time{})
}

// relayOutbound relays the client's datagrams to their destinations until
// the relay socket is closed.
func (c *udpAssociateConn) relayOutbound(ctx context.Context) error {
	buf := make([]byte, 65535)
	clientIP := c.conn.RemoteAddr().(*net.TCPAddr).IP

	for {
		// Wait for data
		n, srcAddr, err := c.relay.ReadFromUDP(buf)
		if err != nil {
			// Normal closure check
			select {
			case <-c.controlDone:
				return nil
			default:
				if err != io.EOF {
					c.logger.Debug().Err(err).Msg("error reading from udp")
				}
				return err
			}
		}

		// Security: Only accept UDP packets from the same IP that established the TCP connection
		if !srcAddr.IP.Equal(clientIP) {
			c.logger.Debug().
				Str("expected", clientIP.String()).
				Str("actual", srcAddr.IP.String()).
				Msg("dropped udp packet from unexpected ip")
			continue
		}

		c.handleDatagram(ctx, srcAddr, buf[:n])
	}
}

// handleDatagram relays one datagram from the client at srcAddr to the
// destination in its header, with the rule that destination selects.
func (c *udpAssociateConn) handleDatagram(
	ctx context.Context,
	srcAddr *net.UDPAddr,
	datagram []byte,
) {
	// Outbound: Client -> Proxy -> Target
	dstAddrStr, payload, err := parseUDPHeader(datagram)
	if err != nil {
		c.logger.Warn().Err(err).Msg("failed to parse socks5 udp header")
		return
	}

	dstAddr, cfg, ok := c.selectRule(ctx, dstAddrStr)
	if !ok {
		return
	}

	// Key: Client Addr -> Target Addr (Zero Allocation Struct). Names
	// that resolve to the same address share the flow, whichever rule
	// each selects.
	key := netutil.NewNATKey(srcAddr.IP, srcAddr.Port, dstAddr.IP, dstAddr.Port)

	if f, ok := c.fetchFlow(key); ok {
		c.logger.Debug().
			Str("key", fmt.Sprintf("%s > %s", srcAddr.String(), dstAddr.String())).
			Msg("session cache hit")

		// The flow idles out after the timeout of the rule its latest
		// datagram selected.
		f.conn.SetTimeout(cfg.Conn.UDPIdleTimeout)

		// Write payload to target
		if _, err := f.conn.Write(payload); err != nil {
			c.logger.Warn().Err(err).Msg("failed to write udp to target")
		}
		return
	}

	c.logger.Debug().
		Str("key", fmt.Sprintf("%s > %s", srcAddr.String(), dstAddr.String())).
		Msg("session cache miss")

	f, err := c.openFlow(ctx, key, srcAddr, dstAddr, cfg)
	if err != nil {
		c.logger.Warn().Err(err).Str("addr", dstAddrStr).Msg("failed to dial udp target")
		return
	}

	// Write payload to target
	if _, err := f.conn.Write(payload); err != nil {
		c.logger.Warn().Err(err).Msg("failed to write udp to target")
	}
}

// selectRule resolves a datagram's destination and selects its rule. It
// reports false when the datagram is to be dropped.
func (c *udpAssociateConn) selectRule(
	ctx context.Context,
	dstAddrStr string,
) (*net.UDPAddr, *config.RuntimeConfig, bool) {
	// parseUDPHeader writes the host and a numeric port.
	dstHost, dstPortStr, _ := net.SplitHostPort(dstAddrStr)
	if dstHost == "" {
		c.logger.Debug().Msg("dropped udp packet with an empty domain name")
		return nil, nil, false
	}
	dstPort, _ := strconv.Atoi(dstPortStr)

	// Flows are dialed and keyed without a zone, so a zoned literal sent as
	// a name, and a link-local address, which is reachable only with a zone,
	// are dropped instead of being looked up or dialed.
	if addr, err := netip.ParseAddr(dstHost); err == nil &&
		(addr.Zone() != "" || netutil.NeedsZone(addr.AsSlice())) {
		c.logger.Debug().
			Str("addr", dstAddrStr).
			Msg("dropped udp packet to a link-local or zoned address")
		return nil, nil, false
	}

	// A domain name is resolved first, then matched together with the
	// address it resolves to. The rule is selected the way it is for
	// CONNECT, but only the first resolved address is used: the resolver
	// returns them in the order of RFC 6724, and a datagram goes to one
	// address.
	dstIPs, dstRule, err := c.h.resolveUDPTarget(ctx, dstHost)
	if err != nil {
		c.logger.Warn().
			Err(err).
			Str("addr", dstAddrStr).
			Msg("failed to resolve udp target")
		return nil, nil, false
	}
	if len(dstIPs) == 0 || dstIPs[0].IsUnspecified() {
		c.logger.Debug().
			Str("addr", dstAddrStr).
			Msg("dropped udp packet to an unspecified address")
		return nil, nil, false
	}
	dstAddr := &net.UDPAddr{IP: dstIPs[0], Port: dstPort}

	// selectFor selects the rule for addr, with candidates, and reports
	// false when that rule blocks the datagram.
	selectFor := func(
		addr net.IP,
		candidates ...*config.Rule,
	) (*config.Rule, *config.RuntimeConfig, bool) {
		matched, cfg := server.SelectRule(
			c.h.ruleSet,
			c.h.cfg,
			"",
			[]net.IP{addr},
			candidates...,
		)
		if matched != nil {
			c.logger.Trace().RawJSON("summary", matched.JSON()).Msg("match")
		}
		if matched != nil && matched.Block {
			// Drop only this datagram; the association stays up for the
			// client's other destinations.
			c.logger.Debug().Str("addr", dstAddrStr).Msg("request is blocked by policy")
			return nil, nil, false
		}
		return matched, cfg, true
	}

	matched, cfg, ok := selectFor(dstAddr.IP, dstRule)
	if !ok {
		return nil, nil, false
	}

	// Under a rule that sets ipv6 = false, the datagram goes to the first
	// IPv4 address instead. That address is matched too, with the rule
	// selected so far as a candidate, so that a rule for it, such as a
	// block, still applies. As the address is IPv4, the rule then selected
	// cannot drop it.
	allowed, err := server.AllowedAddrs(matched, dstIPs)
	if err != nil {
		c.logger.Debug().Err(err).Str("addr", dstAddrStr).Msg("dropped udp packet")
		return nil, nil, false
	}
	if !allowed[0].Equal(dstAddr.IP) {
		if allowed[0].IsUnspecified() {
			c.logger.Debug().
				Str("addr", dstAddrStr).
				Msg("dropped udp packet to an unspecified address")
			return nil, nil, false
		}
		dstAddr = &net.UDPAddr{IP: allowed[0], Port: dstPort}
		if _, cfg, ok = selectFor(dstAddr.IP, matched); !ok {
			return nil, nil, false
		}
	}

	return dstAddr, cfg, true
}

// fetchFlow returns the open flow for key and marks it the most recently
// used.
func (c *udpAssociateConn) fetchFlow(key netutil.NATKey) (*udpFlow, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	f, ok := c.flows[key]
	if ok {
		c.lru.MoveToFront(f.elem)
	}
	return f, ok
}

// openFlow dials dstAddr for the client at srcAddr, sends the fakes of cfg,
// and starts relaying the replies to the client. When the association
// already has its maximum of flows, it closes the least recently used one.
func (c *udpAssociateConn) openFlow(
	ctx context.Context,
	key netutil.NATKey,
	srcAddr *net.UDPAddr,
	dstAddr *net.UDPAddr,
	cfg *config.RuntimeConfig,
) (*udpFlow, error) {
	pktDst := &netutil.Destination{
		Addrs: []net.IP{dstAddr.IP},
		Port:  dstAddr.Port,
	}

	// Register destination for TTL learning when fakes will be sent.
	c.h.desyncer.PrepareHopTrack(pktDst.Addrs, &cfg.UDP)

	rRawConn, err := netutil.DialFastest(ctx, pktDst, "udp", netutil.DialOptions{
		Control: netutil.NoAutoFlowLabelControl(c.logger),
	})
	if err != nil {
		return nil, err
	}

	c.logger.Debug().
		Str("local", rRawConn.LocalAddr().String()).
		Str("remote", rRawConn.RemoteAddr().String()).
		Msg("new remote conn")

	// Fakes share the flow, so the ICMP replies to them reach this socket.
	f := &udpFlow{
		key: key,
		conn: netutil.NewIdleTimeoutConn(
			netutil.NewICMPTolerantConn(rRawConn),
			cfg.Conn.UDPIdleTimeout,
		),
	}
	c.addFlow(f)

	// Send fake packets before real payload (UDP desync)
	if c.h.desyncer != nil && !cfg.UDP.Skip {
		_, _ = c.h.desyncer.Desync(ctx, f.conn.Conn, &cfg.UDP, &cfg.Conn)
	}

	// f.conn is a connected UDP socket, so all responses come from the
	// single remote, dstAddr.
	c.wg.Go(func() { c.relayInbound(f, srcAddr, dstAddr) })

	return f, nil
}

// addFlow adds f as the most recently used flow, closing the least recently
// used one if the association has its maximum of flows.
func (c *udpAssociateConn) addFlow(f *udpFlow) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.h.maxFlows > 0 && c.lru.Len() >= c.h.maxFlows {
		oldest := c.lru.Remove(c.lru.Back()).(*udpFlow)
		delete(c.flows, oldest.key)
		_ = oldest.conn.Close()
	}

	f.elem = c.lru.PushFront(f)
	c.flows[f.key] = f
}

// removeFlow closes f and stops tracking it. A newer flow under the same
// key is left alone.
func (c *udpAssociateConn) removeFlow(f *udpFlow) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.flows[f.key] == f {
		delete(c.flows, f.key)
		c.lru.Remove(f.elem)
	}
	// Closed under mu, so a flow no longer tracked is always closed.
	_ = f.conn.Close()
}

// relayInbound relays the replies on f to the client at clientAddr until f
// is closed or idles out.
func (c *udpAssociateConn) relayInbound(
	f *udpFlow,
	clientAddr *net.UDPAddr,
	targetAddr *net.UDPAddr,
) {
	defer c.removeFlow(f)

	respBuf := make([]byte, 65535)
	for {
		// Read via IdleTimeoutConn so each inbound packet extends the deadline.
		n, err := f.conn.Read(respBuf)
		if err != nil {
			// Connection closed, idled out, or network issues
			return
		}

		c.mu.Lock()
		if c.flows[f.key] == f {
			c.lru.MoveToFront(f.elem)
		}
		c.mu.Unlock()

		// Inbound: Target -> Proxy -> Client
		// Wrap with SOCKS5 Header
		header := createUDPHeaderFromAddr(targetAddr)
		response := append(header, respBuf[:n]...)

		if _, err := c.relay.WriteToUDP(response, clientAddr); err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// A datagram may be lost: drop this one, such as a reply too
			// large to send once the header is added, and keep the flow.
			c.logger.Debug().
				Int("size", len(response)).
				Err(err).
				Msg("dropped a datagram to the client")
		}
	}
}

// resolveUDPTarget returns the addresses of a datagram's destination host:
// the host itself when it is an IP literal, else the addresses h.resolver
// resolves it to, with the DNS options of the domain rule the host matches,
// else the base ones. It also returns that domain rule, nil for an IP
// literal or when none matches.
func (h *UdpAssociateHandler) resolveUDPTarget(
	ctx context.Context,
	host string,
) ([]net.IP, *config.Rule, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil, nil
	}

	nameRule, nameCfg := server.SelectRule(h.ruleSet, h.cfg, host, nil)
	resolved, err := h.resolver.Resolve(ctx, &nameCfg.DNS, host)
	if err != nil {
		return nil, nil, err
	}

	return netutil.IPsFromAddrs(resolved), nameRule, nil
}

func parseUDPHeader(b []byte) (string, []byte, error) {
	if len(b) < 4 {
		return "", nil, fmt.Errorf("header too short")
	}
	// RSV(2) FRAG(1) ATYP(1)
	if b[0] != 0 || b[1] != 0 {
		return "", nil, fmt.Errorf("invalid rsv")
	}
	frag := b[2]
	if frag != 0 {
		return "", nil, fmt.Errorf("fragmentation not supported")
	}

	atyp := b[3]
	var host string
	var pos int

	switch atyp {
	case proto.SOCKS5AddrTypeIPv4:
		if len(b) < 10 {
			return "", nil, fmt.Errorf("header too short for ipv4")
		}
		host = net.IP(b[4:8]).String()
		pos = 8
	case proto.SOCKS5AddrTypeIPv6:
		if len(b) < 22 {
			return "", nil, fmt.Errorf("header too short for ipv6")
		}
		host = net.IP(b[4:20]).String()
		pos = 20
	case proto.SOCKS5AddrTypeFQDN:
		if len(b) < 5 {
			return "", nil, fmt.Errorf("header too short for fqdn")
		}
		l := int(b[4])
		if len(b) < 5+l+2 {
			return "", nil, fmt.Errorf("header too short for fqdn data")
		}
		host = string(b[5 : 5+l])
		pos = 5 + l
	default:
		return "", nil, fmt.Errorf("unsupported atyp: %d", atyp)
	}

	port := binary.BigEndian.Uint16(b[pos : pos+2])
	pos += 2

	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	return addr, b[pos:], nil
}

func createUDPHeaderFromAddr(addr *net.UDPAddr) []byte {
	// RSV(2) FRAG(1) ATYP(1) ...
	buf := make([]byte, 0, 24)
	buf = append(buf, 0, 0, 0) // RSV, FRAG

	ip4 := addr.IP.To4()
	if ip4 != nil {
		buf = append(buf, proto.SOCKS5AddrTypeIPv4)
		buf = append(buf, ip4...)
	} else {
		buf = append(buf, proto.SOCKS5AddrTypeIPv6)
		buf = append(buf, addr.IP.To16()...)
	}

	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(addr.Port))
	buf = append(buf, portBuf...)

	return buf
}
