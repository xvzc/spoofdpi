package socks5

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/desync"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/proto"
	"github.com/xvzc/spoofdpi/internal/rule"
)

// udpRule returns a rule whose config is tagged by its UDP fake count.
func udpRule(
	name string,
	priority uint16,
	domains, cidrs []string,
	fakePreflight uint8,
) *config.Rule {
	r := &config.Rule{
		Name:     name,
		Priority: priority,
		Match:    &config.MatchAttrs{Domains: domains, CIDRs: cidrs},
	}
	r.Config.UDP.FakePreflight = fakePreflight
	return r
}

func newTestUdpAssociateHandler(
	t *testing.T,
	rules ...*config.Rule,
) *UdpAssociateHandler {
	t.Helper()

	rs := rule.NewRuleSet()
	for _, r := range rules {
		require.NoError(t, rs.Add(r))
	}

	base := &config.RuntimeConfig{}
	base.UDP.FakePreflight = 1

	return NewUdpAssociateHandler(zerolog.Nop(), nil, nil, rs, base)
}

// destinationConfigFor runs h.destinationConfig for a destination host the
// way Handle does: only a domain name is passed as the name.
func destinationConfigFor(
	h *UdpAssociateHandler,
	host string,
	addr net.IP,
) (*config.RuntimeConfig, bool) {
	var name string
	if net.ParseIP(host) == nil {
		name = host
	}
	matched, cfg := h.destinationConfig(zerolog.Nop(), name, addr)
	return cfg, matched != nil && matched.Block
}

func TestUdpAssociateHandler_DestinationConfig(t *testing.T) {
	h := newTestUdpAssociateHandler(
		t,
		udpRule("addr", 10, nil, []string{"203.0.113.0/24"}, 2),
		udpRule("domain", 20, []string{"example.com"}, nil, 3),
		udpRule("low domain", 5, []string{"low.example.org"}, nil, 4),
	)

	tcs := []struct {
		name string
		host string
		addr string
		want uint8
	}{
		{"address rule matches", "203.0.113.7", "203.0.113.7", 2},
		{"no rule matches", "198.51.100.7", "198.51.100.7", 1},
		{"domain rule matches", "example.com", "198.51.100.7", 3},
		{"higher-priority domain beats address", "example.com", "203.0.113.7", 3},
		{"higher-priority address beats domain", "low.example.org", "203.0.113.7", 2},
		{"unmatched domain falls back to base", "other.com", "198.51.100.7", 1},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			cfg, blocked := destinationConfigFor(h, tc.host, net.ParseIP(tc.addr))
			assert.Equal(t, tc.want, cfg.UDP.FakePreflight)
			assert.False(t, blocked)
		})
	}
}

func TestUdpAssociateHandler_DestinationConfig_PerDestination(t *testing.T) {
	h := newTestUdpAssociateHandler(
		t,
		udpRule("a", 10, nil, []string{"203.0.113.0/24"}, 2),
		udpRule("b", 10, nil, []string{"198.51.100.0/24"}, 3),
	)

	// One association talks to several destinations; each gets its own config.
	a, _ := destinationConfigFor(h, "203.0.113.7", net.ParseIP("203.0.113.7"))
	b, _ := destinationConfigFor(h, "198.51.100.7",
		net.ParseIP("198.51.100.7"),
	)
	none, _ := destinationConfigFor(h, "192.0.2.7", net.ParseIP("192.0.2.7"))

	assert.Equal(t, uint8(2), a.UDP.FakePreflight)
	assert.Equal(t, uint8(3), b.UDP.FakePreflight)
	assert.Same(t, h.cfg, none)
}

func TestUdpAssociateHandler_DestinationConfig_Block(t *testing.T) {
	block := udpRule("block", 10, nil, []string{"203.0.113.0/24"}, 2)
	block.Block = true
	h := newTestUdpAssociateHandler(
		t,
		block,
		udpRule("allow domain", 20, []string{"example.com"}, nil, 3),
	)

	tcs := []struct {
		name        string
		host        string
		addr        string
		wantBlocked bool
	}{
		{"blocking rule matches", "203.0.113.7", "203.0.113.7", true},
		{"higher-priority rule allows", "example.com", "203.0.113.7", false},
		{"no rule matches", "198.51.100.7", "198.51.100.7", false},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			_, blocked := destinationConfigFor(h, tc.host, net.ParseIP(tc.addr))
			assert.Equal(t, tc.wantBlocked, blocked)
		})
	}
}

func TestUdpAssociateHandler_DestinationConfig_NoRuleSet(t *testing.T) {
	base := &config.RuntimeConfig{}
	h := NewUdpAssociateHandler(zerolog.Nop(), nil, nil, nil, base)

	cfg, blocked := destinationConfigFor(h, "203.0.113.7",
		net.ParseIP("203.0.113.7"),
	)

	assert.Same(t, base, cfg)
	assert.False(t, blocked)
}

// udpAssociation is a running UDP ASSOCIATE seen from the client side.
type udpAssociation struct {
	client *net.UDPConn
	relay  *net.UDPAddr

	// end closes the TCP connection, which ends the association, and
	// waits for Handle to return.
	end func()
}

// startUdpAssociation runs h.Handle on a loopback TCP connection and
// returns the client's UDP socket and the relay address from the reply.
func startUdpAssociation(t *testing.T, h *UdpAssociateHandler) *udpAssociation {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	ctrl, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	srvConn, err := ln.Accept()
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		_ = h.Handle(context.Background(), srvConn, &proto.SOCKS5Request{})
		close(done)
	}()
	var endOnce sync.Once
	end := func() {
		endOnce.Do(func() {
			_ = ctrl.Close()
			<-done
			_ = srvConn.Close()
		})
	}
	t.Cleanup(end)

	// VER REP RSV ATYP(IPv4) ADDR(4) PORT(2)
	reply := make([]byte, 10)
	_, err = io.ReadFull(ctrl, reply)
	require.NoError(t, err)
	require.Equal(t, byte(proto.SOCKS5RCodeSuccess), reply[1])

	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	return &udpAssociation{
		client: client,
		relay: &net.UDPAddr{
			IP:   net.IP(reply[4:8]),
			Port: int(binary.BigEndian.Uint16(reply[8:10])),
		},
		end: end,
	}
}

// send sends payload to dst through the relay.
func (a *udpAssociation) send(t *testing.T, dst *net.UDPAddr, payload string) {
	t.Helper()
	a.sendWithHeader(t, createUDPHeaderFromAddr(dst), payload)
}

// sendToName sends payload through the relay to a destination given as a
// domain name (ATYP 3).
func (a *udpAssociation) sendToName(
	t *testing.T,
	name string,
	port int,
	payload string,
) {
	t.Helper()
	header := []byte{0, 0, 0, proto.SOCKS5AddrTypeFQDN, byte(len(name))}
	header = append(header, name...)
	header = binary.BigEndian.AppendUint16(header, uint16(port))
	a.sendWithHeader(t, header, payload)
}

func (a *udpAssociation) sendWithHeader(t *testing.T, header []byte, payload string) {
	t.Helper()
	_, err := a.client.WriteToUDP(append(header, payload...), a.relay)
	require.NoError(t, err)
}

// receive returns the next payload relayed back to the client.
func (a *udpAssociation) receive(t *testing.T) string {
	t.Helper()
	require.NoError(t, a.client.SetReadDeadline(time.Now().Add(5*time.Second)))
	buf := make([]byte, 1500)
	n, _, err := a.client.ReadFromUDP(buf)
	require.NoError(t, err)
	_, payload, err := parseUDPHeader(buf[:n])
	require.NoError(t, err)
	return string(payload)
}

// key returns the pool key of the client's flow to dst under the matched
// rule (nil for none).
func (a *udpAssociation) key(dst *net.UDPAddr, matched *config.Rule) UDPFlowKey {
	return newUDPFlowKey(a.client.LocalAddr().(*net.UDPAddr), dst, matched)
}

// startUDPEcho runs a loopback UDP server that echoes each datagram.
func startUDPEcho(t *testing.T) *net.UDPAddr {
	t.Helper()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP(buf[:n], addr)
		}
	}()

	return conn.LocalAddr().(*net.UDPAddr)
}

func newRelayingUdpAssociateHandler(
	t *testing.T,
	pool *netutil.ConnRegistry[UDPFlowKey],
	base *config.RuntimeConfig,
	rules ...*config.Rule,
) *UdpAssociateHandler {
	t.Helper()

	rs := rule.NewRuleSet()
	for _, r := range rules {
		require.NoError(t, rs.Add(r))
	}

	return NewUdpAssociateHandler(
		zerolog.Nop(),
		pool,
		desync.NewUDPDesyncer(zerolog.Nop(), nil, nil),
		rs,
		base,
	)
}

func TestUdpAssociateHandler_Handle_BlockedDestination(t *testing.T) {
	blockRule := &config.Rule{
		Name:     "block",
		Priority: 10,
		Block:    true,
		Match:    &config.MatchAttrs{CIDRs: []string{"192.0.2.0/24"}},
	}

	pool := netutil.NewConnRegistry[UDPFlowKey](16)
	h := newRelayingUdpAssociateHandler(t, pool, &config.RuntimeConfig{}, blockRule)
	a := startUdpAssociation(t, h)

	blocked := &net.UDPAddr{IP: net.ParseIP("192.0.2.1").To4(), Port: 9}
	allowed := startUDPEcho(t)

	a.send(t, blocked, "dropped")
	a.send(t, allowed, "hello")

	// The association still relays to other destinations.
	assert.Equal(t, "hello", a.receive(t))

	assert.False(t, pool.Has(a.key(blocked, blockRule)), "blocked destination was dialed")
	assert.True(t, pool.Has(a.key(allowed, nil)))
}

func TestUdpAssociateHandler_Handle_IdleTimeout(t *testing.T) {
	const short, long = 400 * time.Millisecond, time.Hour

	loopbackRule := func(timeout time.Duration) *config.Rule {
		r := &config.Rule{
			Name:     "loopback",
			Priority: 10,
			Match:    &config.MatchAttrs{CIDRs: []string{"127.0.0.0/8"}},
		}
		r.Config.Conn.UDPIdleTimeout = timeout
		return r
	}

	tcs := []struct {
		name        string
		baseTimeout time.Duration
		rules       []*config.Rule
		wantEvicted bool
	}{
		{"base timeout applies without a rule", short, nil, true},
		{
			"rule timeout overrides a longer base",
			long,
			[]*config.Rule{loopbackRule(short)},
			true,
		},
		{
			"rule timeout overrides a shorter base",
			short,
			[]*config.Rule{loopbackRule(long)},
			false,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			base := &config.RuntimeConfig{}
			base.Conn.UDPIdleTimeout = tc.baseTimeout

			pool := netutil.NewConnRegistry[UDPFlowKey](16)
			h := newRelayingUdpAssociateHandler(t, pool, base, tc.rules...)
			a := startUdpAssociation(t, h)

			dst := startUDPEcho(t)
			a.send(t, dst, "hello")
			require.Equal(t, "hello", a.receive(t))

			var matched *config.Rule
			if len(tc.rules) > 0 {
				matched = tc.rules[0]
			}
			key := a.key(dst, matched)
			require.True(t, pool.Has(key))

			// The pool only drops the flow once its relay goroutine has
			// given up on the idle connection.
			if tc.wantEvicted {
				assert.Eventually(t, func() bool {
					return !pool.Has(key)
				}, 5*time.Second, 10*time.Millisecond)
			} else {
				assert.Never(t, func() bool {
					return !pool.Has(key)
				}, 2*short, 10*time.Millisecond)
			}
		})
	}
}

// stubResolver resolves domain names from a fixed table and counts the
// lookups; address literals resolve as usual and aren't counted.
type stubResolver struct {
	names   map[string]net.IP
	lookups atomic.Int32
}

func (r *stubResolver) resolve(network, address string) (*net.UDPAddr, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if net.ParseIP(host) != nil {
		return net.ResolveUDPAddr(network, address)
	}

	r.lookups.Add(1)
	p, err := net.LookupPort(network, port)
	if err != nil {
		return nil, err
	}
	return &net.UDPAddr{IP: r.names[host], Port: p}, nil
}

func TestUdpAssociateHandler_Handle_NameBlock(t *testing.T) {
	const name = "blocked.test"

	blockName := &config.Rule{
		Name:     "block name",
		Priority: 10,
		Block:    true,
		Match:    &config.MatchAttrs{Domains: []string{name}},
	}
	cidrRule := func(cidr string, priority uint16) *config.Rule {
		return &config.Rule{
			Name:     "cidr " + cidr,
			Priority: priority,
			Match:    &config.MatchAttrs{CIDRs: []string{cidr}},
		}
	}

	tcs := []struct {
		name        string
		cidrRule    *config.Rule
		wantRelayed bool
	}{
		{"no cidr rule: dropped", nil, false},
		{"lower-priority cidr rule can't override", cidrRule("127.0.0.0/8", 5), false},
		{"equal-priority cidr rule overrides the name", cidrRule("127.0.0.0/8", 10), true},
		{
			"higher-priority cidr rule elsewhere: dropped",
			cidrRule("192.0.2.0/24", 20),
			false,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			rules := []*config.Rule{blockName}
			if tc.cidrRule != nil {
				rules = append(rules, tc.cidrRule)
			}

			pool := netutil.NewConnRegistry[UDPFlowKey](16)
			h := newRelayingUdpAssociateHandler(t, pool, &config.RuntimeConfig{}, rules...)
			dst := startUDPEcho(t)
			resolver := &stubResolver{names: map[string]net.IP{name: dst.IP}}
			h.resolveUDPAddr = resolver.resolve
			a := startUdpAssociation(t, h)

			a.sendToName(t, name, dst.Port, "by name")
			a.send(t, dst, "by addr")

			// The relay handles datagrams in order, so the first echo
			// shows whether the named one went through.
			want := "by addr"
			if tc.wantRelayed {
				want = "by name"
			}
			assert.Equal(t, want, a.receive(t))
			// The name is resolved before the rule is selected.
			assert.Equal(t, int32(1), resolver.lookups.Load())
		})
	}
}

func TestUdpAssociateHandler_Handle_NameBlockOnFlowOpenedByAddr(t *testing.T) {
	const name = "blocked.test"

	blockName := &config.Rule{
		Name:     "block name",
		Priority: 10,
		Block:    true,
		Match:    &config.MatchAttrs{Domains: []string{name}},
	}

	pool := netutil.NewConnRegistry[UDPFlowKey](16)
	h := newRelayingUdpAssociateHandler(t, pool, &config.RuntimeConfig{}, blockName)
	dst := startUDPEcho(t)
	resolver := &stubResolver{names: map[string]net.IP{name: dst.IP}}
	h.resolveUDPAddr = resolver.resolve
	a := startUdpAssociation(t, h)

	// The address opens a flow to the address the name resolves to.
	a.send(t, dst, "first")
	require.Equal(t, "first", a.receive(t))
	require.True(t, pool.Has(a.key(dst, nil)))

	a.sendToName(t, name, dst.Port, "by name")
	a.send(t, dst, "second")

	assert.Equal(t, "second", a.receive(t))
	assert.Equal(t, 1, pool.Size())
}

func TestUdpAssociateHandler_Handle_AddrBlockOnFlowOpenedByName(t *testing.T) {
	const name = "allowed.test"

	rules := []*config.Rule{
		{
			Name:     "allow name",
			Priority: 20,
			Match:    &config.MatchAttrs{Domains: []string{name}},
		},
		{
			Name:     "block addr",
			Priority: 10,
			Block:    true,
			Match:    &config.MatchAttrs{CIDRs: []string{"127.0.0.0/8"}},
		},
	}

	pool := netutil.NewConnRegistry[UDPFlowKey](16)
	h := newRelayingUdpAssociateHandler(t, pool, &config.RuntimeConfig{}, rules...)
	dst := startUDPEcho(t)
	resolver := &stubResolver{names: map[string]net.IP{name: dst.IP}}
	h.resolveUDPAddr = resolver.resolve
	a := startUdpAssociation(t, h)

	// The name's higher-priority allow rule opens the flow.
	a.sendToName(t, name, dst.Port, "first")
	require.Equal(t, "first", a.receive(t))
	require.True(t, pool.Has(a.key(dst, rules[0])))

	// The address alone is blocked, though the flow it maps to is open.
	a.send(t, dst, "by addr")
	a.sendToName(t, name, dst.Port, "by name")

	assert.Equal(t, "by name", a.receive(t))
}

func TestUdpAssociateHandler_Handle_InvalidDestination(t *testing.T) {
	pool := netutil.NewConnRegistry[UDPFlowKey](16)
	h := newRelayingUdpAssociateHandler(t, pool, &config.RuntimeConfig{})
	dst := startUDPEcho(t)
	// "unset.test" resolves to no address.
	resolver := &stubResolver{names: map[string]net.IP{}}
	h.resolveUDPAddr = resolver.resolve
	a := startUdpAssociation(t, h)

	unspecified := &net.UDPAddr{IP: net.IPv4zero.To4(), Port: dst.Port}
	a.sendToName(t, "", dst.Port, "empty name")
	a.sendToName(t, "unset.test", dst.Port, "no address")
	a.send(t, unspecified, "unspecified")
	a.send(t, dst, "valid")

	assert.Equal(t, "valid", a.receive(t))
	// The empty name is dropped before any lookup.
	assert.Equal(t, int32(1), resolver.lookups.Load())
	assert.False(t, pool.Has(a.key(unspecified, nil)))
	assert.Equal(t, 1, pool.Size())
}

func TestUdpAssociateHandler_Handle_EndReleasesFlows(t *testing.T) {
	// The pool splits its capacity across shards; a small pool could evict
	// one association's flow for the other's by LRU.
	pool := netutil.NewConnRegistry[UDPFlowKey](4096)
	h := newRelayingUdpAssociateHandler(t, pool, &config.RuntimeConfig{})
	dst := startUDPEcho(t)

	other := startUdpAssociation(t, h)
	other.send(t, dst, "other")
	require.Equal(t, "other", other.receive(t))

	baseline := runtime.NumGoroutine()

	a := startUdpAssociation(t, h)
	a.send(t, dst, "hello")
	require.Equal(t, "hello", a.receive(t))
	require.True(t, pool.Has(a.key(dst, nil)))

	a.end()

	assert.False(t, pool.Has(a.key(dst, nil)), "flow outlived its association")
	assert.True(
		t,
		pool.Has(other.key(dst, nil)),
		"another association's flow was evicted",
	)
	// The relay goroutine exits once its connection is closed. Polled here
	// rather than with assert.Eventually, whose own goroutines would count.
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > baseline && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	assert.LessOrEqual(
		t,
		runtime.NumGoroutine(),
		baseline,
		"goroutines outlived the association",
	)

	// The other association keeps relaying.
	other.send(t, dst, "still up")
	assert.Equal(t, "still up", other.receive(t))
}

// flowPerRulePoolSize leaves room for several flows per pool shard; the
// flows of one client and destination under different rules share a shard.
const flowPerRulePoolSize = 4096

func TestUdpAssociateHandler_Handle_FlowPerRule(t *testing.T) {
	const nameA, nameB, nameC = "a.test", "b.test", "c.test"
	const short, long = 400 * time.Millisecond, time.Hour

	domainRule := func(
		priority uint16,
		timeout time.Duration,
		names ...string,
	) *config.Rule {
		r := &config.Rule{
			Name:     names[0],
			Priority: priority,
			Match:    &config.MatchAttrs{Domains: names},
		}
		r.Config.Conn.UDPIdleTimeout = timeout
		return r
	}

	t.Run("names under different rules get their own flows", func(t *testing.T) {
		ruleA := domainRule(10, short, nameA)
		ruleB := domainRule(10, long, nameB)

		pool := netutil.NewConnRegistry[UDPFlowKey](flowPerRulePoolSize)
		h := newRelayingUdpAssociateHandler(t, pool, &config.RuntimeConfig{}, ruleA, ruleB)
		dst := startUDPEcho(t)
		resolver := &stubResolver{names: map[string]net.IP{nameA: dst.IP, nameB: dst.IP}}
		h.resolveUDPAddr = resolver.resolve
		a := startUdpAssociation(t, h)

		a.sendToName(t, nameA, dst.Port, "a")
		require.Equal(t, "a", a.receive(t))
		a.sendToName(t, nameB, dst.Port, "b")
		require.Equal(t, "b", a.receive(t))

		require.True(t, pool.Has(a.key(dst, ruleA)))
		require.True(t, pool.Has(a.key(dst, ruleB)))
		assert.Equal(t, 2, pool.Size())

		// Each flow idles out after its own rule's timeout.
		assert.Eventually(t, func() bool {
			return !pool.Has(a.key(dst, ruleA))
		}, 5*time.Second, 10*time.Millisecond)
		assert.True(t, pool.Has(a.key(dst, ruleB)))
	})

	t.Run("names under the same rule share a flow", func(t *testing.T) {
		shared := domainRule(10, long, nameA, nameB)

		pool := netutil.NewConnRegistry[UDPFlowKey](flowPerRulePoolSize)
		h := newRelayingUdpAssociateHandler(t, pool, &config.RuntimeConfig{}, shared)
		dst := startUDPEcho(t)
		resolver := &stubResolver{names: map[string]net.IP{nameA: dst.IP, nameB: dst.IP}}
		h.resolveUDPAddr = resolver.resolve
		a := startUdpAssociation(t, h)

		a.sendToName(t, nameA, dst.Port, "a")
		require.Equal(t, "a", a.receive(t))
		a.sendToName(t, nameB, dst.Port, "b")
		require.Equal(t, "b", a.receive(t))

		assert.True(t, pool.Has(a.key(dst, shared)))
		assert.Equal(t, 1, pool.Size())
	})

	t.Run("an address uses the address rule's flow", func(t *testing.T) {
		nameRule := domainRule(20, long, nameC)
		addrRule := &config.Rule{
			Name:     "loopback",
			Priority: 10,
			Match:    &config.MatchAttrs{CIDRs: []string{"127.0.0.0/8"}},
		}

		pool := netutil.NewConnRegistry[UDPFlowKey](flowPerRulePoolSize)
		h := newRelayingUdpAssociateHandler(
			t,
			pool,
			&config.RuntimeConfig{},
			nameRule,
			addrRule,
		)
		dst := startUDPEcho(t)
		resolver := &stubResolver{names: map[string]net.IP{nameC: dst.IP}}
		h.resolveUDPAddr = resolver.resolve
		a := startUdpAssociation(t, h)

		a.sendToName(t, nameC, dst.Port, "by name")
		require.Equal(t, "by name", a.receive(t))
		a.send(t, dst, "by addr")
		require.Equal(t, "by addr", a.receive(t))

		assert.True(t, pool.Has(a.key(dst, nameRule)))
		assert.True(t, pool.Has(a.key(dst, addrRule)))
		assert.Equal(t, 2, pool.Size())
	})
}

func TestUdpAssociateHandler_Handle_ReplySourceIsDestination(t *testing.T) {
	const name = "a.test"

	nameRule := &config.Rule{
		Name:     name,
		Priority: 10,
		Match:    &config.MatchAttrs{Domains: []string{name}},
	}

	pool := netutil.NewConnRegistry[UDPFlowKey](flowPerRulePoolSize)
	h := newRelayingUdpAssociateHandler(t, pool, &config.RuntimeConfig{}, nameRule)
	dst := startUDPEcho(t)
	resolver := &stubResolver{names: map[string]net.IP{name: dst.IP}}
	h.resolveUDPAddr = resolver.resolve
	a := startUdpAssociation(t, h)

	// Both flows to dst reply with dst as the source in the SOCKS5 header.
	for _, send := range []func(){
		func() { a.sendToName(t, name, dst.Port, "x") },
		func() { a.send(t, dst, "x") },
	} {
		send()
		require.NoError(t, a.client.SetReadDeadline(time.Now().Add(5*time.Second)))
		buf := make([]byte, 1500)
		n, _, err := a.client.ReadFromUDP(buf)
		require.NoError(t, err)
		src, _, err := parseUDPHeader(buf[:n])
		require.NoError(t, err)
		assert.Equal(t, dst.String(), src)
	}
	assert.Equal(t, 2, pool.Size())
}
