package packet

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xvzc/spoofdpi/internal/cache"
	"github.com/xvzc/spoofdpi/internal/netutil"
)

func TestHopStore_LookupPerProtocol(t *testing.T) {
	server := net.ParseIP("203.0.113.1")

	s := newTestHopStore()
	assert.Equal(t, HopEstimate{Source: HopSourceDefault}, s.Lookup(ProtoTCP, server),
		"a server not in the store gets the default, like an unlearned one")

	s.Register(ProtoTCP, []net.IP{server})
	assert.Equal(t, HopEstimate{Source: HopSourceDefault}, s.Lookup(ProtoTCP, server),
		"registered server has no hop count until learned")
	assert.Equal(t, HopEstimate{Source: HopSourceDefault}, s.Lookup(ProtoUDP, server),
		"not learned over either protocol")

	prev, registered := s.Learn(ProtoTCP, server, 12)
	assert.True(t, registered)
	assert.Equal(t, HopEntry{}, prev)
	assert.Equal(t, HopEstimate{Hops: 12, Source: HopSourceLearned},
		s.Lookup(ProtoTCP, server))

	s.Register(ProtoTCP, []net.IP{server})
	assert.Equal(t, HopEstimate{Hops: 12, Source: HopSourceLearned},
		s.Lookup(ProtoTCP, server), "registering again keeps the learned value")

	prev, registered = s.Learn(ProtoTCP, server, 13)
	assert.True(t, registered)
	assert.Equal(t, HopEntry{Hops: 12, Learned: true}, prev)
}

func TestHopStore_ProtocolsDoNotOverwriteEachOther(t *testing.T) {
	server := net.ParseIP("203.0.113.1")

	s := newTestHopStore()
	s.Register(ProtoTCP, []net.IP{server})
	s.Register(ProtoUDP, []net.IP{server})
	_, registered := s.Learn(ProtoTCP, server, 12)
	assert.True(t, registered)
	_, registered = s.Learn(ProtoUDP, server, 5)
	assert.True(t, registered)

	assert.Equal(t, HopEstimate{Hops: 12, Source: HopSourceLearned},
		s.Lookup(ProtoTCP, server), "a UDP reply does not overwrite the TCP hop count")
	assert.Equal(t, HopEstimate{Hops: 5, Source: HopSourceLearned},
		s.Lookup(ProtoUDP, server))
}

func TestHopStore_FallsBackToOtherProtocol(t *testing.T) {
	server := net.ParseIP("203.0.113.1")

	for _, p := range []Proto{ProtoTCP, ProtoUDP} {
		t.Run(p.String(), func(t *testing.T) {
			s := newTestHopStore()
			s.Register(p, []net.IP{server})
			s.Register(p.other(), []net.IP{server})
			s.Learn(p.other(), server, 9)

			assert.Equal(t, HopEstimate{Hops: 9, Source: HopSourceLearnedOther},
				s.Lookup(p, server), "registered over p, learned over the other")

			s.Learn(p, server, 11)
			assert.Equal(t, HopEstimate{Hops: 11, Source: HopSourceLearned},
				s.Lookup(p, server), "a hop count learned over p wins")
		})
	}

	t.Run("not registered over the protocol", func(t *testing.T) {
		s := newTestHopStore()
		s.Register(ProtoTCP, []net.IP{server})
		s.Learn(ProtoTCP, server, 9)

		assert.Equal(t, HopEstimate{Hops: 9, Source: HopSourceLearnedOther},
			s.Lookup(ProtoUDP, server))
	})
}

func TestHopStore_LearnIgnoresUnregistered(t *testing.T) {
	server := net.ParseIP("203.0.113.1")

	s := newTestHopStore()
	_, registered := s.Learn(ProtoTCP, server, 12)
	assert.False(t, registered)
	assert.Equal(t, HopEstimate{Source: HopSourceDefault}, s.Lookup(ProtoTCP, server))

	s.Register(ProtoUDP, []net.IP{server})
	_, registered = s.Learn(ProtoTCP, server, 12)
	assert.False(t, registered, "registered over the other protocol only")
	assert.False(t, s.entries.Has(HopKey{Proto: ProtoTCP, IP: netutil.NewIPKey(server)}))
	assert.Equal(t, HopEstimate{Source: HopSourceDefault}, s.Lookup(ProtoUDP, server))
}

func TestHopStore_LearnDoesNotReinsertEvicted(t *testing.T) {
	server := net.ParseIP("203.0.113.1")
	key := HopKey{Proto: ProtoTCP, IP: netutil.NewIPKey(server)}

	entries := evictOnGetCache{cache.NewLRUCache[HopKey, HopEntry](1, 16, nil)}
	s := newHopStore(entries)
	s.Register(ProtoTCP, []net.IP{server})

	_, registered := s.Learn(ProtoTCP, server, 12)
	assert.False(t, registered)
	assert.False(t, entries.Has(key))
}

func TestHopKey_ProtocolsShareShard(t *testing.T) {
	ip := netutil.NewIPKey(net.ParseIP("203.0.113.1"))
	assert.Equal(t,
		HopKey{Proto: ProtoTCP, IP: ip}.Bytes(),
		HopKey{Proto: ProtoUDP, IP: ip}.Bytes())
}

func TestHopSource_String(t *testing.T) {
	assert.Equal(t, "learned", HopSourceLearned.String())
	assert.Equal(t, "learned-other", HopSourceLearnedOther.String())
	assert.Equal(t, "default", HopSourceDefault.String())
}

func TestHopStore_MarkWarned(t *testing.T) {
	server := net.ParseIP("203.0.113.1")

	s := newTestHopStore()
	s.Register(ProtoTCP, []net.IP{server})
	s.Register(ProtoUDP, []net.IP{server})
	s.Learn(ProtoTCP, server, 0)

	assert.True(t, s.MarkWarned(ProtoTCP, server), "first warning")
	assert.False(t, s.MarkWarned(ProtoTCP, server), "already warned")

	s.Learn(ProtoTCP, server, 0)
	s.Register(ProtoTCP, []net.IP{server})
	assert.False(t, s.MarkWarned(ProtoTCP, server),
		"learning and registering again keep the mark")
	assert.Equal(t, HopEstimate{Hops: 0, Source: HopSourceLearned},
		s.Lookup(ProtoTCP, server), "the mark does not change the hop count")

	assert.True(t, s.MarkWarned(ProtoUDP, server), "each protocol has its own mark")

	other := net.ParseIP("203.0.113.2")
	assert.True(t, s.MarkWarned(ProtoTCP, other), "a missing destination keeps no mark")
	assert.True(t, s.MarkWarned(ProtoTCP, other))
	assert.False(t, s.entries.Has(HopKey{Proto: ProtoTCP, IP: netutil.NewIPKey(other)}),
		"marking does not insert")
}

func TestHopStore_MarkWarnedOnceConcurrently(t *testing.T) {
	server := net.ParseIP("203.0.113.1")

	s := newTestHopStore()
	s.Register(ProtoTCP, []net.IP{server})

	var firsts atomic.Int32
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if s.MarkWarned(ProtoTCP, server) {
				firsts.Add(1)
			}
		}()
		go func() {
			defer wg.Done()
			s.Learn(ProtoTCP, server, uint8(i))
		}()
	}
	wg.Wait()

	assert.Equal(t, int32(1), firsts.Load())
	assert.False(t, s.MarkWarned(ProtoTCP, server), "no Learn dropped the mark")
}
