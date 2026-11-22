package socks5

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/desync"
	"github.com/xvzc/spoofdpi/internal/logging"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/proto"
	"github.com/xvzc/spoofdpi/internal/rule"
)

type UdpAssociateHandler struct {
	logger   zerolog.Logger
	pool     *netutil.ConnRegistry[netutil.NATKey]
	desyncer *desync.UDPDesyncer
	ruleSet  *rule.RuleSet
	cfg      *config.RuntimeConfig

	// resolveUDPAddr resolves the destinations that clients send as domain
	// names.
	resolveUDPAddr func(network, address string) (*net.UDPAddr, error)
}

func NewUdpAssociateHandler(
	logger zerolog.Logger,
	pool *netutil.ConnRegistry[netutil.NATKey],
	desyncer *desync.UDPDesyncer,
	ruleSet *rule.RuleSet,
	cfg *config.RuntimeConfig,
) *UdpAssociateHandler {
	return &UdpAssociateHandler{
		logger:   logger,
		pool:     pool,
		desyncer: desyncer,
		ruleSet:  ruleSet,
		cfg:      cfg,

		resolveUDPAddr: net.ResolveUDPAddr,
	}
}

func (h *UdpAssociateHandler) Handle(
	ctx context.Context,
	lConn net.Conn,
	req *proto.SOCKS5Request,
) error {
	logger := logging.WithLocalScope(ctx, h.logger, "udp_associate")

	// 1. Listen on a random UDP port
	lTCPAddr := lConn.LocalAddr().(*net.TCPAddr) // SOCKS5 listens on TCP
	lUDPConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: lTCPAddr.IP, Port: 0})
	if err != nil {
		logger.Error().Err(err).Msg("failed to create udp listener")
		_ = proto.SOCKS5FailureResponse().Write(lConn)
		return err
	}
	defer netutil.CloseConns(lUDPConn)

	logger.Debug().
		Str("addr", lUDPConn.LocalAddr().String()).
		Str("network", lUDPConn.LocalAddr().Network()).
		Msg("new conn")

	lUDPAddr := lUDPConn.LocalAddr().(*net.UDPAddr)

	logger.Debug().
		Str("bind_addr", lUDPAddr.String()).
		Msg("socks5 udp associate established")

		// 2. Reply with the bound address
	err = proto.SOCKS5SuccessResponse().Bind(lUDPAddr.IP).Port(lUDPAddr.Port).Write(lConn)
	if err != nil {
		logger.Error().Err(err).Msg("failed to write socks5 success reply")
		return err
	}

	// 3. Keep TCP Alive & Relay
	// According to [RFC1928](https://datatracker.ietf.org/doc/html/rfc1928#section-6),
	// > A UDP association terminates when the TCP connection that the UDP
	// > ASSOCIATE request arrived on terminates.
	// Therefore, we need to monitor TCP for closure.
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, lConn) // Block until TCP closes
		close(done)                       // Close the channel to signal UDP handler to exit
		_ = lUDPConn.Close()              // Force ReadFromUDP to unblock and avoid goroutine leak
	}()

	// The remote flows this association created end with it.
	flows := newAssociationFlows(h.pool)
	defer flows.releaseAll()

	buf := make([]byte, 65535)
	rTCPAddr := lConn.RemoteAddr().(*net.TCPAddr).IP

	for {
		// Wait for data
		n, srcAddr, err := lUDPConn.ReadFromUDP(buf)
		if err != nil {
			// Normal closure check
			select {
			case <-done:
				return nil
			default:
				if err != io.EOF {
					logger.Debug().Err(err).Msg("error reading from udp")
				}
				return err
			}
		}

		// Security: Only accept UDP packets from the same IP that established the TCP connection
		if !srcAddr.IP.Equal(rTCPAddr) {
			logger.Debug().
				Str("expected", rTCPAddr.String()).
				Str("actual", srcAddr.IP.String()).
				Msg("dropped udp packet from unexpected ip")
			continue
		}

		// Outbound: Client -> Proxy -> Target
		dstAddrStr, payload, err := parseUDPHeader(buf[:n])
		if err != nil {
			logger.Warn().Err(err).Msg("failed to parse socks5 udp header")
			continue
		}

		// A domain name is resolved first, then matched together with the
		// address it resolves to.
		dstHost, _, _ := net.SplitHostPort(dstAddrStr)
		var dstName string
		if net.ParseIP(dstHost) == nil {
			if dstHost == "" {
				logger.Debug().Msg("dropped udp packet with an empty domain name")
				continue
			}
			dstName = dstHost
		}

		// Resolve address to construct Destination
		dstAddr, err := h.resolveUDPAddr("udp", dstAddrStr)
		if err != nil {
			logger.Warn().
				Err(err).
				Str("addr", dstAddrStr).
				Msg("failed to resolve udp target")
			continue
		}
		if dstAddr.IP == nil || dstAddr.IP.IsUnspecified() {
			logger.Debug().
				Str("addr", dstAddrStr).
				Msg("dropped udp packet to an unspecified address")
			continue
		}

		matched, cfg := h.destinationConfig(logger, dstName, dstAddr.IP)
		if matched != nil && matched.Block {
			// Drop only this datagram; the association stays up for the
			// client's other destinations.
			logger.Debug().Str("addr", dstAddrStr).Msg("request is blocked by policy")
			continue
		}

		// Key: Client Addr -> Target Addr (Zero Allocation Struct). Names
		// that resolve to the same address share the flow, whichever rule
		// each selects.
		key := netutil.NewNATKey(srcAddr.IP, srcAddr.Port, dstAddr.IP, dstAddr.Port)

		// Check if connection already exists in the pool
		cachedConn, cached := h.pool.Fetch(key)
		if cached {
			logger.Debug().
				Str("key", fmt.Sprintf("%s > %s", srcAddr.String(), dstAddr.String())).
				Msg("session cache hit")

			// The flow idles out after the timeout of the rule its latest
			// datagram selected.
			cachedConn.SetTimeout(cfg.Conn.UDPIdleTimeout)

			// Write payload to target
			if _, err := cachedConn.Write(payload); err != nil {
				logger.Warn().Err(err).Msg("failed to write udp to target")
			}
			continue
		}

		logger.Debug().
			Str("key", fmt.Sprintf("%s > %s", srcAddr.String(), dstAddr.String())).
			Msg("session cache miss")

		pktDst := &netutil.Destination{
			Addrs: []net.IP{dstAddr.IP},
			Port:  dstAddr.Port,
		}

		// Register destination for TTL learning when fakes will be sent.
		h.desyncer.PrepareHopTrack(pktDst.Addrs, &cfg.UDP)

		rRawConn, err := netutil.DialFastest(ctx, pktDst, "udp", 0, nil)
		if err != nil {
			logger.Warn().Err(err).Str("addr", dstAddrStr).Msg("failed to dial udp target")
			continue
		}

		// Add to pool (pool handles LRU eviction and deadline)
		// returns IdleTimeoutConn with the actual net.Conn inside
		// Fakes share the flow, so the ICMP replies to them reach this socket.
		rConn := h.pool.Store(
			key,
			netutil.NewICMPTolerantConn(rRawConn),
			cfg.Conn.UDPIdleTimeout,
		)
		flows.add(key, rConn)

		// Send fake packets before real payload (UDP desync)
		if h.desyncer != nil && !cfg.UDP.Skip {
			_, _ = h.desyncer.Desync(ctx, rConn.Conn, &cfg.UDP, &cfg.Conn)
		}

		// Start a goroutine to read from the target and forward to the client.
		// rConn is a connected UDP socket, so all responses come from the single remote.
		// Using rConn.Read() (via IdleTimeoutConn) properly extends the idle deadline
		// on each inbound packet, preventing premature timeout on asymmetric flows.
		// dstAddr is already *net.UDPAddr (resolved above), same as rConn.RemoteAddr().
		go h.relayInboundUDP(logger, lUDPConn, rConn, srcAddr, dstAddr, key, flows)

		// Write payload to target
		if _, err := rConn.Write(payload); err != nil {
			logger.Warn().Err(err).Msg("failed to write udp to target")
		}
	}
}

// destinationConfig selects the rule for one destination of an
// association and returns it with the config it applies; matched is nil
// when no rule matches, and cfg is then the base config. Rules match the
// way they do for CONNECT: by the resolved address and, when the client
// sent a domain name (name is empty otherwise), by that name; the
// higher-priority match wins, the address on a tie.
func (h *UdpAssociateHandler) destinationConfig(
	logger zerolog.Logger,
	name string,
	addr net.IP,
) (matched *config.Rule, cfg *config.RuntimeConfig) {
	if h.ruleSet == nil {
		return nil, h.cfg
	}

	var nameMatch *config.Rule
	if name != "" {
		nameMatch = h.ruleSet.Search(
			[]rule.Query{{Type: rule.MatchTypeDomain, Value: name}},
		)
	}
	addrMatch := h.ruleSet.Search(
		[]rule.Query{{Type: rule.MatchTypeAddr, Value: addr.String()}},
	)
	matched = rule.HigherPriority(addrMatch, nameMatch)
	if matched == nil {
		return nil, h.cfg
	}

	logger.Trace().RawJSON("summary", matched.JSON()).Msg("match")
	return matched, &matched.Config
}

func (h *UdpAssociateHandler) relayInboundUDP(
	logger zerolog.Logger,
	lUDPConn *net.UDPConn,
	rConn *netutil.IdleTimeoutConn,
	clientAddr *net.UDPAddr,
	targetAddr *net.UDPAddr,
	key netutil.NATKey,
	flows *associationFlows,
) {
	defer flows.release(key, rConn)

	respBuf := make([]byte, 65535)
	for {
		// Read via IdleTimeoutConn so each inbound packet extends the deadline.
		n, err := rConn.Read(respBuf)
		if err != nil {
			// Connection closed or network issues
			return
		}

		// Inbound: Target -> Proxy -> Client
		// Wrap with SOCKS5 Header
		header := createUDPHeaderFromAddr(targetAddr)
		response := append(header, respBuf[:n]...)

		if _, err := lUDPConn.WriteToUDP(response, clientAddr); err != nil {
			// If we can't write back to the client, it might be gone or network issue.
			// Exit this goroutine to avoid busy looping.
			logger.Warn().Err(err).Msg("failed to write udp to client")
			return
		}
	}
}

// associationFlows tracks the remote flows that one UDP association put in
// the pool, so they can end with the association: "A UDP association
// terminates when the TCP connection that the UDP ASSOCIATE request arrived
// on terminates" (RFC 1928, section 6).
type associationFlows struct {
	pool *netutil.ConnRegistry[netutil.NATKey]

	mu    sync.Mutex
	conns map[netutil.NATKey]*netutil.IdleTimeoutConn
}

func newAssociationFlows(
	pool *netutil.ConnRegistry[netutil.NATKey],
) *associationFlows {
	return &associationFlows{
		pool:  pool,
		conns: make(map[netutil.NATKey]*netutil.IdleTimeoutConn),
	}
}

func (f *associationFlows) add(key netutil.NATKey, conn *netutil.IdleTimeoutConn) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.conns[key] = conn
}

// release stops tracking conn and evicts it from the pool, which closes it.
// A newer flow stored under the same key is left alone.
func (f *associationFlows) release(key netutil.NATKey, conn *netutil.IdleTimeoutConn) {
	f.mu.Lock()
	if f.conns[key] == conn {
		delete(f.conns, key)
	}
	f.mu.Unlock()

	f.pool.EvictFunc(key, func(v *netutil.IdleTimeoutConn) bool { return v == conn })
}

// releaseAll evicts every flow still tracked; their relay goroutines exit
// once their connections are closed.
func (f *associationFlows) releaseAll() {
	f.mu.Lock()
	conns := f.conns
	f.conns = make(map[netutil.NATKey]*netutil.IdleTimeoutConn)
	f.mu.Unlock()

	for key, conn := range conns {
		f.pool.EvictFunc(key, func(v *netutil.IdleTimeoutConn) bool { return v == conn })
	}
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
