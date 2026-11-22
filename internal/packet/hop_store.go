package packet

import (
	"net"
	"sync"

	"github.com/xvzc/spoofdpi/internal/cache"
	"github.com/xvzc/spoofdpi/internal/netutil"
)

// hopStoreCapacity is the number of destinations a HopStore keeps. An IP
// takes one entry per protocol.
const hopStoreCapacity = 16384

// Proto is the transport protocol a hop count is learned over.
type Proto uint8

const (
	ProtoTCP Proto = iota
	ProtoUDP
)

func (p Proto) String() string {
	if p == ProtoUDP {
		return "udp"
	}
	return "tcp"
}

// other returns the protocol that is not p.
func (p Proto) other() Proto {
	if p == ProtoUDP {
		return ProtoTCP
	}
	return ProtoUDP
}

// HopKey is the key of a destination in a HopStore.
type HopKey struct {
	Proto Proto
	IP    netutil.IPKey
}

// Bytes returns the IP's bytes only, so that both protocols of an IP share
// a cache shard.
func (k HopKey) Bytes() []byte { return k.IP.Bytes() }

// HopEntry is a HopStore entry.
type HopEntry struct {
	Hops    uint8 // the learned hop count; 0 until Learned
	Learned bool  // learned from a captured packet, not only registered
	Warned  bool  // a warning about the destination was logged
}

// HopSource is where the hop count of a HopEstimate comes from.
type HopSource uint8

const (
	// HopSourceDefault: no hop count was learned for the IP, or it is not
	// in the store, so the configured default applies.
	HopSourceDefault HopSource = iota
	// HopSourceLearned: learned over the protocol it was looked up for.
	HopSourceLearned
	// HopSourceLearnedOther: learned over the other protocol only.
	HopSourceLearnedOther
)

func (s HopSource) String() string {
	switch s {
	case HopSourceLearned:
		return "learned"
	case HopSourceLearnedOther:
		return "learned-other"
	default:
		return "default"
	}
}

// HopEstimate is the hop count to a destination, and where it comes from.
type HopEstimate struct {
	Hops   uint8 // the learned hop count; 0 unless Learned
	Source HopSource
}

// Learned reports whether Hops was learned, over either protocol.
func (e HopEstimate) Learned() bool {
	return e.Source == HopSourceLearned || e.Source == HopSourceLearnedOther
}

// HopReader is what the desyncers need from a HopStore.
type HopReader interface {
	// Register registers addrs for hop-count learning over p.
	Register(p Proto, addrs []net.IP)
	// Lookup returns the hop count to ip over p.
	Lookup(p Proto, ip net.IP) HopEstimate
	// MarkWarned marks the destination ip over p as warned about, and
	// reports whether it was not yet.
	MarkWarned(p Proto, ip net.IP) bool
}

var _ HopReader = (*HopStore)(nil)

// HopStore keeps the hop counts learned per destination, a protocol and an
// IP, in an LRU cache. Only registered destinations are learned.
type HopStore struct {
	entries cache.Cache[HopKey, HopEntry]
	// mu makes each read-modify-write of an entry atomic, so that Learn
	// and MarkWarned do not lose each other's fields. Register only
	// inserts, and Lookup only reads.
	mu sync.Mutex
}

// NewHopStore returns an empty HopStore.
func NewHopStore() *HopStore {
	return newHopStore(cache.NewLRUCache[HopKey, HopEntry](16, hopStoreCapacity, nil))
}

func newHopStore(entries cache.Cache[HopKey, HopEntry]) *HopStore {
	return &HopStore{entries: entries}
}

// Register registers addrs for hop-count learning over p. Destinations
// that are already registered keep their entry.
func (s *HopStore) Register(p Proto, addrs []net.IP) {
	for _, ip := range addrs {
		s.entries.Set(
			HopKey{Proto: p, IP: netutil.NewIPKey(ip)},
			HopEntry{},
			cache.Options().WithSkipExisting(true),
		)
	}
}

// Learn records hops as the hop count to ip over p if that destination is
// registered, and reports whether it is. prev is its entry before.
func (s *HopStore) Learn(
	p Proto,
	ip net.IP,
	hops uint8,
) (prev HopEntry, registered bool) {
	key := HopKey{Proto: p, IP: netutil.NewIPKey(ip)}
	s.mu.Lock()
	defer s.mu.Unlock()
	// The update-only Set decides whether key is registered, so a key
	// evicted after this Get is not re-inserted.
	prev, _ = s.entries.Get(key)
	registered = s.entries.Set(
		key,
		HopEntry{Hops: hops, Learned: true, Warned: prev.Warned},
		cache.Options().WithUpdateExistingOnly(true),
	)
	return prev, registered
}

// Lookup returns the hop count to ip over p: the one learned over p, or
// else the one learned over the other protocol, or else HopSourceDefault,
// whether ip is in the store or not.
func (s *HopStore) Lookup(p Proto, ip net.IP) HopEstimate {
	ipKey := netutil.NewIPKey(ip)
	if own, _ := s.entries.Get(HopKey{Proto: p, IP: ipKey}); own.Learned {
		return HopEstimate{Hops: own.Hops, Source: HopSourceLearned}
	}
	if other, _ := s.entries.Get(HopKey{Proto: p.other(), IP: ipKey}); other.Learned {
		return HopEstimate{Hops: other.Hops, Source: HopSourceLearnedOther}
	}
	return HopEstimate{Source: HopSourceDefault}
}

// MarkWarned marks the destination ip over p as warned about, and reports
// whether it was not yet. A destination missing from the store, never
// registered or evicted, keeps no mark, so it is always reported as not
// warned about.
func (s *HopStore) MarkWarned(p Proto, ip net.IP) bool {
	key := HopKey{Proto: p, IP: netutil.NewIPKey(ip)}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries.Get(key)
	if !ok {
		return true
	}
	if e.Warned {
		return false
	}
	e.Warned = true
	s.entries.Set(key, e, cache.Options().WithUpdateExistingOnly(true))
	return true
}
