package packet

import (
	"errors"
	"io"
	"sync/atomic"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/cache"
	"github.com/xvzc/spoofdpi/internal/capture"
)

// filterHandle is a capture handle that has no packets to read, and that
// records the filter installed on it or rejects it with setErr.
type filterHandle struct {
	captureHandle
	setErr error
	filter []capture.BPFInstruction
	reads  atomic.Int32
}

func (h *filterHandle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	h.reads.Add(1)
	return nil, gopacket.CaptureInfo{}, io.EOF
}

func (h *filterHandle) SetBPFRawInstructionFilter(f []capture.BPFInstruction) error {
	if h.setErr != nil {
		return h.setErr
	}
	h.filter = f
	return nil
}

// mustFilter returns the program of filter for an Ethernet link.
func mustFilter(
	t *testing.T,
	filter func(layers.LinkType) ([]capture.BPFInstruction, error),
) []capture.BPFInstruction {
	t.Helper()

	prog, err := filter(layers.LinkTypeEthernet)
	require.NoError(t, err)
	return prog
}

func TestSniffer_StartCapturing(t *testing.T) {
	rejected := errors.New("program rejected")

	tcs := []struct {
		name   string
		start  func(h capture.Handle) error
		filter []capture.BPFInstruction
	}{
		{
			"tcp",
			func(h capture.Handle) error {
				return NewTCPSniffer(zerolog.Nop(), h, newTestHopStore(), nil).StartCapturing()
			},
			mustFilter(t, capture.SynAckFilter),
		},
		{
			"udp",
			func(h capture.Handle) error {
				return NewUDPSniffer(zerolog.Nop(), h, newTestHopStore()).StartCapturing()
			},
			mustFilter(t, capture.UDPFilter),
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name+" installs its filter", func(t *testing.T) {
			h := &filterHandle{}
			require.NoError(t, tc.start(h))
			assert.Equal(t, tc.filter, h.filter)
		})

		t.Run(tc.name+" fails on an unsupported link type", func(t *testing.T) {
			h := &linkHandle{&filterHandle{}, layers.LinkTypeLinuxSLL}
			err := tc.start(h)
			require.ErrorIs(t, err, capture.ErrUnsupportedLinkType)
			assert.Empty(t, h.filter)
			assert.Zero(t, h.reads.Load(), "must not read unfiltered packets")
		})

		t.Run(tc.name+" fails when the filter is rejected", func(t *testing.T) {
			h := &filterHandle{setErr: rejected}
			err := tc.start(h)
			require.ErrorIs(t, err, rejected)
			assert.Zero(t, h.reads.Load(), "must not read unfiltered packets")
		})
	}
}

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
	none := HopPolicy{Default: 8, Max: 255, Offset: -1}

	tcs := []struct {
		name   string
		policy HopPolicy
		est    HopEstimate
		want   uint8
	}{
		{"learned hop count plus the default offset", none, learned(19), 18},
		{
			"hop count learned over the other protocol",
			none,
			HopEstimate{Hops: 19, Source: HopSourceLearnedOther},
			18,
		},
		{"registered default", none, HopEstimate{}, 7},
		{
			"registered default comes from the policy",
			HopPolicy{Default: 12, Max: 255, Offset: -1},
			HopEstimate{},
			11,
		},
		{"at least 1", none, learned(0), 1},
		{
			"offset applies to learned counts",
			HopPolicy{Default: 8, Max: 255, Offset: -5},
			learned(16),
			11,
		},
		{
			"offset applies to the other protocol's count",
			HopPolicy{Default: 8, Max: 255, Offset: -5},
			HopEstimate{Hops: 16, Source: HopSourceLearnedOther},
			11,
		},
		{
			"offset applies to the default",
			HopPolicy{Default: 8, Max: 255, Offset: -5},
			HopEstimate{},
			3,
		},
		{
			"zero offset sends fakes with the hop count",
			HopPolicy{Default: 8, Max: 255},
			learned(16),
			16,
		},
		{
			"positive offset",
			HopPolicy{Default: 8, Max: 255, Offset: 2},
			learned(16),
			18,
		},
		{
			"max caps an overestimate",
			HopPolicy{Default: 8, Max: 20, Offset: -1},
			learned(43),
			19,
		},
		{
			"min raises a small count",
			HopPolicy{Default: 8, Min: 10, Max: 255, Offset: -1},
			learned(5),
			9,
		},
		{
			"default is clamped too",
			HopPolicy{Default: 8, Min: 10, Max: 255, Offset: -1},
			HopEstimate{},
			9,
		},
		{
			"bounds apply before the offset",
			HopPolicy{Default: 8, Min: 3, Max: 10, Offset: -5},
			learned(16),
			5,
		},
		{
			"at least 1 after a large negative offset",
			HopPolicy{Default: 8, Min: 3, Max: 255, Offset: -100},
			learned(16),
			1,
		},
		{
			"at most 255 after a positive offset",
			HopPolicy{Default: 8, Max: 255, Offset: 10},
			learned(250),
			255,
		},
		{
			"zero max means no bound",
			HopPolicy{Default: 8, Offset: -1},
			learned(43),
			42,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.policy.TTL(tc.est))
		})
	}
}

// ttlBeforeOffsetChange is the TTL formula before hop-count-offset applied
// to every hop count and replaced the fixed minus 1: Offset added to a
// learned hop count only, the result clamped to [Min, Max] and to at least
// 2, minus 1.
func ttlBeforeOffsetChange(p HopPolicy, est HopEstimate) uint8 {
	hops := int(p.Default)
	if est.Learned() {
		hops = int(est.Hops) + int(p.Offset)
	}
	upper := int(p.Max)
	if upper == 0 {
		upper = 255
	}
	hops = min(max(hops, int(p.Min)), upper)
	hops = min(max(hops, 2), 255)
	return uint8(hops - 1)
}

// TestHopPolicyTTL_DefaultOffsetKeepsTTL checks that the default offset of
// -1 gives the TTLs the default offset of 0 gave before, for every hop
// count, learned or not, and every hop count default and bounds.
func TestHopPolicyTTL_DefaultOffsetKeepsTTL(t *testing.T) {
	for _, bounds := range [][2]uint8{
		{0, 255}, // the defaults
		{0, 0},
		{0, 1},
		{0, 20},
		{1, 1},
		{3, 255},
		{10, 15},
		{11, 15},
		{254, 255},
		{255, 255},
	} {
		for _, def := range []uint8{1, 2, 8, 64, 255} {
			before := HopPolicy{Default: def, Min: bounds[0], Max: bounds[1], Offset: 0}
			after := before
			after.Offset = -1

			ests := []HopEstimate{{Source: HopSourceDefault}}
			for hops := range 256 {
				ests = append(ests,
					HopEstimate{Hops: uint8(hops), Source: HopSourceLearned},
					HopEstimate{Hops: uint8(hops), Source: HopSourceLearnedOther},
				)
			}
			for _, est := range ests {
				if !assert.Equal(t,
					ttlBeforeOffsetChange(before, est), after.TTL(est),
					"policy %+v, estimate %+v", after, est,
				) {
					return
				}
			}
		}
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
}
