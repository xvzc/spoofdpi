package desync

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/netutil"
)

// fakeClock is a clock that moves only when told to.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// fakeLookup answers lookups from a table, nil for addresses not in it,
// and counts them per address.
type fakeLookup struct {
	mu      sync.Mutex
	answers map[netip.Addr]error
	calls   map[netip.Addr]int
}

func newFakeLookup(answers map[netip.Addr]error) *fakeLookup {
	return &fakeLookup{answers: answers, calls: map[netip.Addr]int{}}
}

func (l *fakeLookup) lookup(dst netip.Addr) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls[dst]++
	return l.answers[dst]
}

func (l *fakeLookup) count(dst string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.calls[netip.MustParseAddr(dst)]
}

// v6Off is the static gate main wires: fakes to IPv4 only.
var v6Off = NewStaticGate(nil, &FakesOffError{
	Family: netutil.FamilyV6,
	Kind:   FakesOffIPv6Unsupported,
	Reason: "IPv6 fakes are not supported yet",
})

func dstViaVPN(dst string) *FakesOffError {
	return &FakesOffError{
		Family:    netutil.FamilyV4,
		Kind:      FakesOffDstViaVPN,
		Interface: "utun4",
		Reason:    fmt.Sprintf("the route to %s goes through a VPN (utun4)", dst),
	}
}

func TestNewRouteGate_Defaults(t *testing.T) {
	g := NewRouteGate(v6Off, newFakeLookup(nil).lookup, RouteGateOptions{})
	assert.Equal(t, 5*time.Second, g.ttl)
	assert.NotNil(t, g.now)
}

// A split-tunnel VPN carries some servers: those are denied, the others
// allowed.
func TestRouteGate_SplitTunnelVPN(t *testing.T) {
	const viaVPN, direct = "10.20.0.5", "203.0.113.1"
	deny := dstViaVPN(viaVPN)
	l := newFakeLookup(map[netip.Addr]error{netip.MustParseAddr(viaVPN): deny})
	g := NewRouteGate(v6Off, l.lookup, RouteGateOptions{})

	assert.Same(t, deny, g.CanFake(net.ParseIP(viaVPN)))
	assert.NoError(t, g.CanFake(net.ParseIP(direct)))
	assert.NoError(
		t,
		g.CanFake(net.ParseIP("::ffff:"+direct)),
		"mapped is the same server",
	)

	assert.Equal(t, 1, l.count(viaVPN))
	assert.Equal(t, 1, l.count(direct), "the mapped address hits the cache")
}

// The static gate answers first: an IPv6 server is never looked up.
func TestRouteGate_StaticFirst(t *testing.T) {
	l := newFakeLookup(nil)
	g := NewRouteGate(v6Off, l.lookup, RouteGateOptions{})

	var off *FakesOffError
	require.ErrorAs(t, g.CanFake(net.ParseIP("2001:db8::1")), &off)
	assert.Equal(t, FakesOffIPv6Unsupported, off.Kind)
	assert.Error(t, g.CanFake(nil))
	assert.Empty(t, l.calls)
}

// Both answers are kept for the TTL, and looked up again after it.
func TestRouteGate_TTL(t *testing.T) {
	const denied, allowed = "10.20.0.5", "203.0.113.1"
	clock := newFakeClock()
	l := newFakeLookup(
		map[netip.Addr]error{netip.MustParseAddr(denied): dstViaVPN(denied)},
	)
	g := NewRouteGate(
		v6Off,
		l.lookup,
		RouteGateOptions{TTL: 5 * time.Second, Now: clock.Now},
	)

	for range 3 {
		assert.Error(t, g.CanFake(net.ParseIP(denied)))
		assert.NoError(t, g.CanFake(net.ParseIP(allowed)))
	}
	assert.Equal(t, 1, l.count(denied))
	assert.Equal(t, 1, l.count(allowed))

	clock.Advance(5*time.Second - time.Nanosecond)
	assert.Error(t, g.CanFake(net.ParseIP(denied)))
	assert.NoError(t, g.CanFake(net.ParseIP(allowed)))
	assert.Equal(t, 1, l.count(denied), "fresh until the TTL")

	// The route changed: the server is now direct.
	l.mu.Lock()
	delete(l.answers, netip.MustParseAddr(denied))
	l.mu.Unlock()
	clock.Advance(time.Nanosecond)
	assert.NoError(t, g.CanFake(net.ParseIP(denied)))
	assert.NoError(t, g.CanFake(net.ParseIP(allowed)))
	assert.Equal(t, 2, l.count(denied))
	assert.Equal(t, 2, l.count(allowed))
}

// The cache keeps at most Capacity servers, dropping the least recently
// used.
func TestRouteGate_LRUBound(t *testing.T) {
	l := newFakeLookup(nil)
	g := NewRouteGate(v6Off, l.lookup, RouteGateOptions{Capacity: 2})

	a, b, c := "203.0.113.1", "203.0.113.2", "203.0.113.3"
	require.NoError(t, g.CanFake(net.ParseIP(a)))
	require.NoError(t, g.CanFake(net.ParseIP(b)))
	require.NoError(t, g.CanFake(net.ParseIP(a))) // a is now the most recent
	require.NoError(t, g.CanFake(net.ParseIP(c))) // drops b

	require.NoError(t, g.CanFake(net.ParseIP(a)))
	require.NoError(t, g.CanFake(net.ParseIP(c)))
	assert.Equal(t, 1, l.count(a))
	assert.Equal(t, 1, l.count(c))

	require.NoError(t, g.CanFake(net.ParseIP(b)))
	assert.Equal(t, 2, l.count(b), "b was dropped")

	for i := range 100 {
		require.NoError(t, g.CanFake(net.IPv4(198, 51, 100, byte(i))))
	}
	require.NoError(t, g.CanFake(net.ParseIP(a)))
	assert.Equal(t, 2, l.count(a), "100 newer servers dropped a")
}

// A lookup that allows a server because the route could not be read is
// cached like any other answer.
func TestRouteGate_FailOpenCached(t *testing.T) {
	const dst = "203.0.113.1"
	clock := newFakeClock()
	var calls int
	failOpen := func(netip.Addr) error {
		calls++
		return nil // as dstFakeCheck answers when Lookup fails
	}
	g := NewRouteGate(v6Off, failOpen, RouteGateOptions{Now: clock.Now})

	assert.NoError(t, g.CanFake(net.ParseIP(dst)))
	clock.Advance(time.Second)
	assert.NoError(t, g.CanFake(net.ParseIP(dst)))
	assert.Equal(t, 1, calls)
}

// Concurrent calls for one server share one lookup; calls for other
// servers do not wait for it.
func TestRouteGate_Concurrent(t *testing.T) {
	const slow = "10.20.0.5"
	release := make(chan struct{})
	l := newFakeLookup(map[netip.Addr]error{netip.MustParseAddr(slow): dstViaVPN(slow)})
	lookup := func(dst netip.Addr) error {
		if dst == netip.MustParseAddr(slow) {
			<-release
		}
		return l.lookup(dst)
	}
	g := NewRouteGate(v6Off, lookup, RouteGateOptions{})

	const callers = 50
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	for range callers {
		wg.Go(func() { errs <- g.CanFake(net.ParseIP(slow)) })
	}

	// Other servers are answered while the slow lookup blocks.
	for i := range 20 {
		assert.NoError(t, g.CanFake(net.IPv4(203, 0, 113, byte(i+1))))
	}

	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		assert.Error(t, err)
	}
	assert.Equal(t, 1, l.count(slow), "callers for one server share a lookup")
}

func TestRouteGate_PanickingLookupDoesNotBlockLaterCalls(t *testing.T) {
	clock := newFakeClock()
	dst := netip.MustParseAddr("10.20.0.5")
	calls := 0
	g := NewRouteGate(NewStaticGate(nil, nil), func(netip.Addr) error {
		calls++
		if calls == 1 {
			panic("lookup failed")
		}
		return nil
	}, RouteGateOptions{TTL: time.Second, Now: clock.Now})

	assert.Panics(t, func() { _ = g.CanFake(net.IP(dst.AsSlice())) })
	clock.Advance(2 * time.Second)

	done := make(chan error, 1)
	go func() { done <- g.CanFake(net.IP(dst.AsSlice())) }()
	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("a call after a panicking lookup blocked")
	}
	assert.Equal(t, 2, calls)
}
