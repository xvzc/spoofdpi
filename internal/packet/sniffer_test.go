package packet

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xvzc/spoofdpi/internal/cache"
	"github.com/xvzc/spoofdpi/internal/netutil"
)

// evictOnGetCache deletes each key right after returning it, as if LRU
// eviction ran between a sniffer's lookup and its write.
type evictOnGetCache struct {
	cache.Cache[netutil.IPKey, HopEntry]
}

func (c evictOnGetCache) Get(key netutil.IPKey) (HopEntry, bool) {
	e, ok := c.Cache.Get(key)
	c.Delete(key)
	return e, ok
}

func TestHopPolicyTTL(t *testing.T) {
	none := HopPolicy{Default: 8, Max: 255}

	tcs := []struct {
		name   string
		policy HopPolicy
		entry  HopEntry
		ok     bool
		want   uint8
	}{
		{"learned hop count minus 1", none, HopEntry{Hops: 19, Learned: true}, true, 18},
		{"registered default", none, HopEntry{}, true, 7},
		{
			"registered default comes from the policy",
			HopPolicy{Default: 12, Max: 255},
			HopEntry{},
			true, 11,
		},
		{"unknown server", none, HopEntry{}, false, 254},
		{"at least 1", none, HopEntry{Hops: 0, Learned: true}, true, 1},
		{
			"offset applies to learned counts",
			HopPolicy{Default: 8, Max: 255, Offset: -5},
			HopEntry{Hops: 16, Learned: true},
			true, 10,
		},
		{
			"offset does not apply to the default",
			HopPolicy{Default: 8, Max: 255, Offset: -5},
			HopEntry{},
			true, 7,
		},
		{
			"max caps an overestimate",
			HopPolicy{Default: 8, Max: 20},
			HopEntry{Hops: 43, Learned: true},
			true, 19,
		},
		{
			"min raises a small count",
			HopPolicy{Default: 8, Min: 10, Max: 255},
			HopEntry{Hops: 5, Learned: true},
			true, 9,
		},
		{
			"default is clamped too",
			HopPolicy{Default: 8, Min: 10, Max: 255},
			HopEntry{},
			true, 9,
		},
		{
			"offset is clamped too",
			HopPolicy{Default: 8, Min: 3, Max: 255, Offset: -100},
			HopEntry{Hops: 16, Learned: true},
			true, 2,
		},
		{
			"zero max means no bound",
			HopPolicy{Default: 8},
			HopEntry{Hops: 43, Learned: true},
			true, 42,
		},
		{
			"unknown server is capped by max",
			HopPolicy{Default: 8, Max: 20},
			HopEntry{},
			false, 19,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.policy.TTL(tc.entry, tc.ok))
		})
	}
}
