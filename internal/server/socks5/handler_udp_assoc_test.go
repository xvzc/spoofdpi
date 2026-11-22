package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
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
	"github.com/xvzc/spoofdpi/internal/packet"
	"github.com/xvzc/spoofdpi/internal/proto"
	"github.com/xvzc/spoofdpi/internal/rule"
)

// udpAssociation is a running UDP ASSOCIATE seen from the client side.
type udpAssociation struct {
	client *net.UDPConn
	relay  *net.UDPAddr
	conn   *udpAssociateConn

	// end closes the TCP connection, which ends the association, and
	// waits for Handle to return.
	end func()
}

// startUdpAssociation serves an association of h, as Handle does, on a
// loopback TCP connection and returns the client's UDP socket and the relay
// address from the reply.
func startUdpAssociation(t *testing.T, h *UdpAssociateHandler) *udpAssociation {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	ctrl, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	srvConn, err := ln.Accept()
	require.NoError(t, err)

	c := newUdpAssociateConn(h, srvConn, &proto.SOCKS5Request{})
	done := make(chan struct{})
	go func() {
		_ = c.serve(context.Background())
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
		conn: c,
		end:  end,
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

// key returns the key of the client's flow to dst.
func (a *udpAssociation) key(dst *net.UDPAddr) netutil.NATKey {
	src := a.client.LocalAddr().(*net.UDPAddr)
	return netutil.NewNATKey(src.IP, src.Port, dst.IP, dst.Port)
}

// flow returns the association's open flow from the client to dst, or nil.
func (a *udpAssociation) flow(dst *net.UDPAddr) *udpFlow {
	a.conn.mu.Lock()
	defer a.conn.mu.Unlock()
	return a.conn.flows[a.key(dst)]
}

// hasFlow reports whether the association has an open flow from the client
// to dst.
func (a *udpAssociation) hasFlow(dst *net.UDPAddr) bool {
	return a.flow(dst) != nil
}

// flowCount returns the number of the association's open flows.
func (a *udpAssociation) flowCount() int {
	a.conn.mu.Lock()
	defer a.conn.mu.Unlock()
	return len(a.conn.flows)
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

	h := newRelayingUdpAssociateHandler(t, &config.RuntimeConfig{}, blockRule)
	a := startUdpAssociation(t, h)

	blocked := &net.UDPAddr{IP: net.ParseIP("192.0.2.1").To4(), Port: 9}
	allowed := startUDPEcho(t)

	a.send(t, blocked, "dropped")
	a.send(t, allowed, "hello")

	// The association still relays to other destinations.
	assert.Equal(t, "hello", a.receive(t))

	assert.False(t, a.hasFlow(blocked), "blocked destination was dialed")
	assert.True(t, a.hasFlow(allowed))
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

			h := newRelayingUdpAssociateHandler(t, base, tc.rules...)
			a := startUdpAssociation(t, h)

			dst := startUDPEcho(t)
			a.send(t, dst, "hello")
			require.Equal(t, "hello", a.receive(t))

			flow := a.flow(dst)
			require.NotNil(t, flow)

			// The association only drops the flow once its relay goroutine
			// has given up on the idle connection.
			if !tc.wantEvicted {
				assert.Never(t, func() bool {
					return !a.hasFlow(dst)
				}, 2*short, 10*time.Millisecond)
				return
			}

			assert.Eventually(t, func() bool {
				return !a.hasFlow(dst)
			}, 5*time.Second, 10*time.Millisecond)
			// The expired flow's socket is closed.
			_, err := flow.conn.Write([]byte("x"))
			assert.ErrorIs(t, err, net.ErrClosed)

			// The association stays up and opens a new flow.
			a.send(t, dst, "again")
			assert.Equal(t, "again", a.receive(t))
			assert.True(t, a.hasFlow(dst))
		})
	}
}

// stubResolver resolves domain names from a fixed table and counts the
// lookups; a name not in the table resolves to no address, and a name in
// errs fails with its error. It records the DNS options of each name's
// latest lookup.
type stubResolver struct {
	names   map[string]net.IP
	errs    map[string]error
	lookups atomic.Int32
	opts    sync.Map // domain -> *config.DNSOptions
}

func (r *stubResolver) Resolve(
	_ context.Context,
	opts *config.DNSOptions,
	domain string,
) ([]netip.Addr, error) {
	r.lookups.Add(1)
	r.opts.Store(domain, opts)
	if err, ok := r.errs[domain]; ok {
		return nil, err
	}
	ip, ok := r.names[domain]
	if !ok {
		return nil, nil
	}
	addr, _ := netip.AddrFromSlice(ip)
	return []netip.Addr{addr.Unmap()}, nil
}

// lookupOpts returns the DNS options of domain's latest lookup, or nil.
func (r *stubResolver) lookupOpts(domain string) *config.DNSOptions {
	opts, ok := r.opts.Load(domain)
	if !ok {
		return nil
	}
	return opts.(*config.DNSOptions)
}

func TestUdpAssociateHandler_Handle_NameLookup(t *testing.T) {
	ruleDNS := &config.Rule{
		Name:     "rule dns",
		Priority: 10,
		Match:    &config.MatchAttrs{Domains: []string{"rule.test"}},
	}
	ruleDNS.Config.DNS.HTTPSURL = "rule"
	base := &config.RuntimeConfig{}
	base.DNS.HTTPSURL = "base"

	h := newRelayingUdpAssociateHandler(t, base, ruleDNS)
	dst := startUDPEcho(t)
	resolver := &stubResolver{
		names: map[string]net.IP{"rule.test": dst.IP, "base.test": dst.IP},
		errs:  map[string]error{"fail.test": errors.New("lookup failed")},
	}
	h.resolver = resolver
	a := startUdpAssociation(t, h)

	// A failed lookup drops only that datagram.
	a.sendToName(t, "fail.test", dst.Port, "failed")
	a.sendToName(t, "rule.test", dst.Port, "by rule")
	assert.Equal(t, "by rule", a.receive(t))
	a.sendToName(t, "base.test", dst.Port, "by base")
	assert.Equal(t, "by base", a.receive(t))

	assert.Equal(t, int32(3), resolver.lookups.Load())
	if opts := resolver.lookupOpts("rule.test"); assert.NotNil(t, opts) {
		assert.Equal(t, "rule", opts.HTTPSURL)
	}
	assert.Same(t, &base.DNS, resolver.lookupOpts("base.test"))
	assert.Same(t, &base.DNS, resolver.lookupOpts("fail.test"))
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

			h := newRelayingUdpAssociateHandler(t, &config.RuntimeConfig{}, rules...)
			dst := startUDPEcho(t)
			resolver := &stubResolver{names: map[string]net.IP{name: dst.IP}}
			h.resolver = resolver
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

	h := newRelayingUdpAssociateHandler(t, &config.RuntimeConfig{}, blockName)
	dst := startUDPEcho(t)
	resolver := &stubResolver{names: map[string]net.IP{name: dst.IP}}
	h.resolver = resolver
	a := startUdpAssociation(t, h)

	// The address opens a flow to the address the name resolves to.
	a.send(t, dst, "first")
	require.Equal(t, "first", a.receive(t))
	require.True(t, a.hasFlow(dst))

	a.sendToName(t, name, dst.Port, "by name")
	a.send(t, dst, "second")

	assert.Equal(t, "second", a.receive(t))
	assert.Equal(t, 1, a.flowCount())
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

	h := newRelayingUdpAssociateHandler(t, &config.RuntimeConfig{}, rules...)
	dst := startUDPEcho(t)
	resolver := &stubResolver{names: map[string]net.IP{name: dst.IP}}
	h.resolver = resolver
	a := startUdpAssociation(t, h)

	// The name's higher-priority allow rule opens the flow.
	a.sendToName(t, name, dst.Port, "first")
	require.Equal(t, "first", a.receive(t))
	require.True(t, a.hasFlow(dst))

	// The address alone is blocked, though the flow it maps to is open.
	a.send(t, dst, "by addr")
	a.sendToName(t, name, dst.Port, "by name")

	assert.Equal(t, "by name", a.receive(t))
}

func TestUdpAssociateHandler_Handle_InvalidDestination(t *testing.T) {
	h := newRelayingUdpAssociateHandler(t, &config.RuntimeConfig{})
	dst := startUDPEcho(t)
	// "unset.test" resolves to no address.
	resolver := &stubResolver{names: map[string]net.IP{}}
	h.resolver = resolver
	a := startUdpAssociation(t, h)

	unspecified := &net.UDPAddr{IP: net.IPv4zero.To4(), Port: dst.Port}
	a.sendToName(t, "", dst.Port, "empty name")
	a.sendToName(t, "unset.test", dst.Port, "no address")
	a.send(t, unspecified, "unspecified")
	a.send(t, dst, "valid")

	assert.Equal(t, "valid", a.receive(t))
	// The empty name is dropped before any lookup.
	assert.Equal(t, int32(1), resolver.lookups.Load())
	assert.False(t, a.hasFlow(unspecified))
	assert.Equal(t, 1, a.flowCount())
}

func TestUdpAssociateHandler_Handle_EndReleasesFlows(t *testing.T) {
	h := newRelayingUdpAssociateHandler(t, &config.RuntimeConfig{})
	dst := startUDPEcho(t)

	other := startUdpAssociation(t, h)
	other.send(t, dst, "other")
	require.Equal(t, "other", other.receive(t))

	baseline := goroutinesIn(udpAssocFile)

	a := startUdpAssociation(t, h)
	a.send(t, dst, "hello")
	require.Equal(t, "hello", a.receive(t))
	require.True(t, a.hasFlow(dst))

	a.end()

	assert.False(t, a.hasFlow(dst), "flow outlived its association")
	assert.True(
		t,
		other.hasFlow(dst),
		"another association's flow was closed",
	)
	// Handle waits for the goroutines it started; the other association's
	// remain.
	assert.Equal(
		t,
		baseline,
		goroutinesIn(udpAssocFile),
		"goroutines outlived the association",
	)

	// The other association keeps relaying.
	other.send(t, dst, "still up")
	assert.Equal(t, "still up", other.receive(t))
}

// countingFakeWriter counts the fake packets written to it.
type countingFakeWriter struct {
	writes atomic.Int32
}

func (w *countingFakeWriter) WriteCraftedPacket(
	_ context.Context,
	_, _ net.Addr,
	_ uint8,
	payload []byte,
) (int, error) {
	w.writes.Add(1)
	return len(payload), nil
}

// unlearnedHops knows no hop counts, so fakes use the default TTL.
type unlearnedHops struct{}

func (unlearnedHops) Register(packet.Proto, []net.IP) {}

func (unlearnedHops) Lookup(packet.Proto, net.IP) packet.HopEstimate {
	return packet.HopEstimate{Source: packet.HopSourceDefault}
}

func (unlearnedHops) MarkWarned(packet.Proto, net.IP) bool { return true }

func TestUdpAssociateHandler_Handle_RulePerDatagram(t *testing.T) {
	const nameA, nameB = "a.test", "b.test"
	const short, long = 400 * time.Millisecond, time.Hour

	domainRule := func(name string, timeout time.Duration, fakes uint8) *config.Rule {
		r := &config.Rule{
			Name:     name,
			Priority: 10,
			Match:    &config.MatchAttrs{Domains: []string{name}},
		}
		r.Config.Conn.UDPIdleTimeout = timeout
		r.Config.UDP.FakePreflight = fakes
		return r
	}

	// start runs an association whose datagrams to nameA and nameB reach
	// the returned echo server.
	start := func(
		t *testing.T,
		rules ...*config.Rule,
	) (*UdpAssociateHandler, *net.UDPAddr) {
		t.Helper()

		h := newRelayingUdpAssociateHandler(t, &config.RuntimeConfig{}, rules...)
		dst := startUDPEcho(t)
		resolver := &stubResolver{names: map[string]net.IP{nameA: dst.IP, nameB: dst.IP}}
		h.resolver = resolver
		return h, dst
	}

	t.Run("names under different rules share a flow", func(t *testing.T) {
		h, dst := start(t, domainRule(nameA, long, 0), domainRule(nameB, long, 0))
		a := startUdpAssociation(t, h)

		a.sendToName(t, nameA, dst.Port, "a")
		require.Equal(t, "a", a.receive(t))
		a.sendToName(t, nameB, dst.Port, "b")
		require.Equal(t, "b", a.receive(t))

		assert.True(t, a.hasFlow(dst))
		assert.Equal(t, 1, a.flowCount())
	})

	t.Run("a blocked name is dropped on an open flow", func(t *testing.T) {
		blockB := domainRule(nameB, long, 0)
		blockB.Block = true
		h, dst := start(t, domainRule(nameA, long, 0), blockB)
		a := startUdpAssociation(t, h)

		a.sendToName(t, nameA, dst.Port, "first")
		require.Equal(t, "first", a.receive(t))

		a.sendToName(t, nameB, dst.Port, "blocked")
		a.sendToName(t, nameA, dst.Port, "second")

		// The relay handles datagrams in order, so the blocked one would
		// have been echoed first.
		assert.Equal(t, "second", a.receive(t))
		assert.Equal(t, 1, a.flowCount())
	})

	t.Run("idle timeout follows the latest datagram's rule", func(t *testing.T) {
		tcs := []struct {
			name          string
			first, second time.Duration
			wantEvicted   bool
		}{
			{"short then long", short, long, false},
			{"long then short", long, short, true},
		}

		for _, tc := range tcs {
			t.Run(tc.name, func(t *testing.T) {
				h, dst := start(
					t,
					domainRule(nameA, tc.first, 0),
					domainRule(nameB, tc.second, 0),
				)
				a := startUdpAssociation(t, h)

				a.sendToName(t, nameA, dst.Port, "a")
				require.Equal(t, "a", a.receive(t))
				a.sendToName(t, nameB, dst.Port, "b")
				require.Equal(t, "b", a.receive(t))

				if tc.wantEvicted {
					assert.Eventually(t, func() bool {
						return !a.hasFlow(dst)
					}, 5*time.Second, 10*time.Millisecond)
				} else {
					assert.Never(t, func() bool {
						return !a.hasFlow(dst)
					}, 2*short, 10*time.Millisecond)
				}
			})
		}
	})

	t.Run("fakes are sent once with the first datagram's rule", func(t *testing.T) {
		tcs := []struct {
			name      string
			first     string
			second    string
			wantFakes int32
		}{
			{"a first", nameA, nameB, 2},
			{"b first", nameB, nameA, 3},
		}

		for _, tc := range tcs {
			t.Run(tc.name, func(t *testing.T) {
				h, dst := start(t, domainRule(nameA, long, 2), domainRule(nameB, long, 3))
				writer := &countingFakeWriter{}
				h.desyncer = desync.NewUDPDesyncer(zerolog.Nop(), writer, unlearnedHops{})
				a := startUdpAssociation(t, h)

				for _, name := range []string{tc.first, tc.second, tc.first} {
					a.sendToName(t, name, dst.Port, name)
					require.Equal(t, name, a.receive(t))
				}

				assert.Equal(t, tc.wantFakes, writer.writes.Load())
			})
		}
	})
}

func TestUdpAssociateHandler_Handle_ReplySourceIsDestination(t *testing.T) {
	const name = "a.test"

	nameRule := &config.Rule{
		Name:     name,
		Priority: 10,
		Match:    &config.MatchAttrs{Domains: []string{name}},
	}

	h := newRelayingUdpAssociateHandler(t, &config.RuntimeConfig{}, nameRule)
	dst := startUDPEcho(t)
	resolver := &stubResolver{names: map[string]net.IP{name: dst.IP}}
	h.resolver = resolver
	a := startUdpAssociation(t, h)

	// Replies on the flow to dst carry dst as the source in the SOCKS5
	// header, whether the datagram was sent to the name or the address.
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
	assert.Equal(t, 1, a.flowCount())
}

// udpAssocFile is the path suffix of the handler's source, for goroutinesIn.
const udpAssocFile = "/socks5/handler_udp_assoc.go"

func TestNewUdpAssociateHandler_MaxFlows(t *testing.T) {
	h := newRelayingUdpAssociateHandler(t, &config.RuntimeConfig{})
	assert.Equal(t, 256, h.maxFlows)
}

func TestUdpAssociateHandler_Handle_FlowLimit(t *testing.T) {
	h := newRelayingUdpAssociateHandler(t, &config.RuntimeConfig{})
	h.maxFlows = 2
	a := startUdpAssociation(t, h)
	d1, d2, d3 := startUDPEcho(t), startUDPEcho(t), startUDPEcho(t)

	a.send(t, d1, "d1")
	require.Equal(t, "d1", a.receive(t))
	a.send(t, d2, "d2")
	require.Equal(t, "d2", a.receive(t))
	evicted := a.flow(d2)
	require.NotNil(t, evicted)

	// d1 is used again, so d2 is the least recently used flow.
	a.send(t, d1, "d1 again")
	require.Equal(t, "d1 again", a.receive(t))

	a.send(t, d3, "d3")
	require.Equal(t, "d3", a.receive(t))

	assert.Equal(t, 2, a.flowCount())
	assert.True(t, a.hasFlow(d1))
	assert.True(t, a.hasFlow(d3))
	assert.False(t, a.hasFlow(d2), "the least recently used flow stayed open")
	_, err := evicted.conn.Write([]byte("x"))
	assert.ErrorIs(t, err, net.ErrClosed, "the evicted flow's socket is open")

	// A datagram to the evicted destination opens a new flow, evicting the
	// now least recently used d1.
	a.send(t, d2, "d2 again")
	assert.Equal(t, "d2 again", a.receive(t))
	assert.Equal(t, 2, a.flowCount())
	assert.False(t, a.hasFlow(d1))
}

func TestUdpAssociateHandler_Handle_EndClosesRelayAndFlows(t *testing.T) {
	h := newRelayingUdpAssociateHandler(t, &config.RuntimeConfig{})
	a := startUdpAssociation(t, h)
	d1, d2 := startUDPEcho(t), startUDPEcho(t)

	var flows []*udpFlow
	for _, dst := range []*net.UDPAddr{d1, d2} {
		a.send(t, dst, "hello")
		require.Equal(t, "hello", a.receive(t))
		flows = append(flows, a.flow(dst))
	}
	require.Equal(t, 2, a.flowCount())

	a.end()

	assert.Zero(t, goroutinesIn(udpAssocFile), "goroutines outlived the association")
	assert.Zero(t, a.flowCount())
	for _, f := range flows {
		_, err := f.conn.Write([]byte("x"))
		assert.ErrorIs(t, err, net.ErrClosed, "a flow's socket outlived the association")
	}
	relay, err := net.ListenUDP("udp", a.relay)
	if assert.NoError(t, err, "the relay socket outlived the association") {
		_ = relay.Close()
	}
}

func TestUdpAssociateHandler_Handle_NoFlowLimit(t *testing.T) {
	h := newRelayingUdpAssociateHandler(t, &config.RuntimeConfig{})
	h.maxFlows = 0
	a := startUdpAssociation(t, h)

	for _, dst := range []*net.UDPAddr{startUDPEcho(t), startUDPEcho(t)} {
		a.send(t, dst, "hello")
		require.Equal(t, "hello", a.receive(t))
	}
	assert.Equal(t, 2, a.flowCount())
}
