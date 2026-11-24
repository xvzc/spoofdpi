package packet

import (
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/xvzc/spoofdpi/internal/cache"
	"github.com/xvzc/spoofdpi/internal/netutil"
)

// Defaults of RouteGateOptions.
const (
	DefaultRouteGateTTL      = 5 * time.Second
	DefaultRouteGateCapacity = 4096
)

// RouteGateOptions configures a RouteGate. Zero fields take their
// defaults.
type RouteGateOptions struct {
	// TTL is how long the answer for a destination is kept.
	TTL time.Duration
	// Capacity is how many destinations are kept. The least recently used
	// one is dropped first.
	Capacity int
	// Now returns the current time. Tests replace it.
	Now func() time.Time
}

// RouteGate is a FakeCapability that checks each destination: first by
// its address family, as a StaticGate does, then by a lookup, such as of
// the route to it. The answers of the lookup, nil or not, are cached per
// destination address.
type RouteGate struct {
	static *StaticGate
	lookup func(netip.Addr) error
	ttl    time.Duration
	now    func() time.Time
	cache  cache.Cache[netutil.IPKey, routeGateEntry]

	mu       sync.Mutex
	inflight map[netutil.IPKey]*routeGateLookup
}

var _ FakeCapability = (*RouteGate)(nil)

// routeGateEntry is the cached answer for a destination.
type routeGateEntry struct {
	err     error
	expires time.Time
}

// routeGateLookup is a lookup in progress, which callers for the same
// destination wait for instead of looking it up again.
type routeGateLookup struct {
	done chan struct{}
	err  error
}

// NewRouteGate returns a gate that asks static first and lookup for the
// destinations static allows. lookup returns nil when fake packets can be
// sent to the address, which is unmapped, and an error that says why they
// cannot otherwise.
func NewRouteGate(
	static *StaticGate,
	lookup func(netip.Addr) error,
	o RouteGateOptions,
) *RouteGate {
	if o.TTL <= 0 {
		o.TTL = DefaultRouteGateTTL
	}
	if o.Capacity <= 0 {
		o.Capacity = DefaultRouteGateCapacity
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &RouteGate{
		static: static,
		lookup: lookup,
		ttl:    o.TTL,
		now:    o.Now,
		// One shard keeps the bound and the LRU order exact.
		cache:    cache.NewLRUCache[netutil.IPKey, routeGateEntry](1, o.Capacity, nil),
		inflight: make(map[netutil.IPKey]*routeGateLookup),
	}
}

// CanFake returns the error of the static gate for dst, if any, and the
// answer of the lookup for dst otherwise, from the cache while it is
// fresh. Concurrent calls for the same destination share one lookup.
func (g *RouteGate) CanFake(dst net.IP) error {
	if err := g.static.CanFake(dst); err != nil {
		return err
	}
	key := netutil.NewIPKey(dst)
	if e, ok := g.cached(key); ok {
		return e.err
	}

	g.mu.Lock()
	if l, ok := g.inflight[key]; ok {
		g.mu.Unlock()
		<-l.done
		return l.err
	}
	// A lookup may have finished since the check above.
	if e, ok := g.cached(key); ok {
		g.mu.Unlock()
		return e.err
	}
	l := &routeGateLookup{done: make(chan struct{})}
	g.inflight[key] = l
	g.mu.Unlock()

	// A panicking lookup must not leave the waiters, or later callers, blocked.
	defer func() {
		g.cache.Set(key, routeGateEntry{err: l.err, expires: g.now().Add(g.ttl)}, nil)
		g.mu.Lock()
		delete(g.inflight, key)
		g.mu.Unlock()
		close(l.done)
	}()
	addr, _ := netip.AddrFromSlice(dst)
	l.err = g.lookup(addr.Unmap())
	return l.err
}

// cached returns the cached answer for key while it is fresh.
func (g *RouteGate) cached(key netutil.IPKey) (routeGateEntry, bool) {
	e, ok := g.cache.Get(key)
	if !ok || !g.now().Before(e.expires) {
		return routeGateEntry{}, false
	}
	return e, true
}
