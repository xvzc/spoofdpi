package packet

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xvzc/spoofdpi/internal/cache"
)

// evictOnGetCache deletes each key right after returning it, as if LRU
// eviction ran between a store's lookup and its write.
type evictOnGetCache struct {
	cache.Cache[HopKey, HopEntry]
}

func (c evictOnGetCache) Get(key HopKey) (HopEntry, bool) {
	e, ok := c.Cache.Get(key)
	c.Delete(key)
	return e, ok
}

func TestHopPolicyTTL(t *testing.T) {
	none := HopPolicy{Default: 8, Max: 255}

	tcs := []struct {
		name   string
		policy HopPolicy
		est    HopEstimate
		want   uint8
	}{
		{"learned hop count minus 1", none, learned(19), 18},
		{
			"hop count learned over the other protocol",
			none,
			HopEstimate{Hops: 19, Source: HopSourceLearnedOther},
			18,
		},
		{"registered default", none, HopEstimate{}, 7},
		{
			"registered default comes from the policy",
			HopPolicy{Default: 12, Max: 255},
			HopEstimate{},
			11,
		},
		{"unknown server", none, HopEstimate{Source: HopSourceNone}, 254},
		{"at least 1", none, learned(0), 1},
		{
			"offset applies to learned counts",
			HopPolicy{Default: 8, Max: 255, Offset: -5},
			learned(16),
			10,
		},
		{
			"offset does not apply to the default",
			HopPolicy{Default: 8, Max: 255, Offset: -5},
			HopEstimate{},
			7,
		},
		{
			"max caps an overestimate",
			HopPolicy{Default: 8, Max: 20},
			learned(43),
			19,
		},
		{
			"min raises a small count",
			HopPolicy{Default: 8, Min: 10, Max: 255},
			learned(5),
			9,
		},
		{
			"default is clamped too",
			HopPolicy{Default: 8, Min: 10, Max: 255},
			HopEstimate{},
			9,
		},
		{
			"offset is clamped too",
			HopPolicy{Default: 8, Min: 3, Max: 255, Offset: -100},
			learned(16),
			2,
		},
		{
			"zero max means no bound",
			HopPolicy{Default: 8},
			learned(43),
			42,
		},
		{
			"unknown server is capped by max",
			HopPolicy{Default: 8, Max: 20},
			HopEstimate{Source: HopSourceNone},
			19,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.policy.TTL(tc.est))
		})
	}
}

// learned returns the estimate of a hop count learned over the protocol it
// is looked up for.
func learned(hops uint8) HopEstimate {
	return HopEstimate{Hops: hops, Source: HopSourceLearned}
}

func TestHopPolicyHops(t *testing.T) {
	p := HopPolicy{Default: 8, Max: 255, Offset: -5}

	assert.Equal(t, uint8(16), p.Hops(learned(16)), "before the offset")
	assert.Equal(
		t,
		uint8(16),
		p.Hops(HopEstimate{Hops: 16, Source: HopSourceLearnedOther}),
	)
	assert.Equal(t, uint8(8), p.Hops(HopEstimate{}))
	assert.Equal(t, uint8(255), p.Hops(HopEstimate{Source: HopSourceNone}))
}
