package desync

import (
	"bytes"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/cache"
	"github.com/xvzc/spoofdpi/internal/logging"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/packetio/capture"
)

// captureHandle is a capture handle that reads nothing, accepts any
// filter, and records whether it was closed. Tests embed it and override
// what they observe.
type captureHandle struct {
	closed bool
}

func (h *captureHandle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	return nil, gopacket.CaptureInfo{}, nil
}

func (h *captureHandle) SetBPFRawInstructionFilter(
	[]capture.BPFInstruction,
) error {
	return nil
}

func (h *captureHandle) ClearBPF() error { return nil }

func (h *captureHandle) LinkType() layers.LinkType { return layers.LinkTypeEthernet }
func (h *captureHandle) Close()                    { h.closed = true }

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

// mustFilter returns the IPv4 program of filter for an Ethernet link.
func mustFilter(
	t *testing.T,
	filter func(layers.LinkType, netutil.FamilySet) ([]capture.BPFInstruction, error),
) []capture.BPFInstruction {
	t.Helper()

	prog, err := filter(layers.LinkTypeEthernet, netutil.NewFamilySet(netutil.FamilyV4))
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
				return NewTCPSniffer(
					"",
					zerolog.Nop(),
					h,
					newTestHopStore(),
					nil,
				).StartCapturing()
			},
			mustFilter(t, capture.SynAckFilter),
		},
		{
			"udp",
			func(h capture.Handle) error {
				return NewUDPSniffer("", zerolog.Nop(), h, newTestHopStore()).StartCapturing()
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

// replayHandle is a capture handle that reads each of its packets once and
// then reports the end of the capture.
type replayHandle struct {
	filterHandle
	packets [][]byte
}

func (h *replayHandle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	if len(h.packets) == 0 {
		return nil, gopacket.CaptureInfo{}, io.EOF
	}
	data := h.packets[0]
	h.packets = h.packets[1:]
	return data, gopacket.CaptureInfo{CaptureLength: len(data), Length: len(data)}, nil
}

// lockedBuffer is a log destination that the capture goroutine and the test
// can use at the same time.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// traceIDLogger returns a logger that records the trace ID of each event's
// context, as the application's logger does, in logs.
func traceIDLogger(logs io.Writer) zerolog.Logger {
	return zerolog.New(logs).Level(zerolog.TraceLevel).Hook(
		zerolog.HookFunc(func(e *zerolog.Event, _ zerolog.Level, _ string) {
			id, _ := logging.TraceIDFromContext(e.GetCtx())
			e.Str("trace_id", id)
		}),
	)
}

func TestSniffer_CaptureLogsCarryRunID(t *testing.T) {
	const runID = "0123456789abcdef"
	server := net.ParseIP("203.0.113.1")
	client := net.ParseIP("192.168.1.11")
	hops := newTestHopStore()

	tcs := []struct {
		name  string
		proto Proto
		// logs is how many of the two packets log.
		logs  int
		start func(runID string, logger zerolog.Logger, h capture.Handle) error
		pkt   gopacket.Packet
	}{
		{
			"tcp", ProtoTCP, 2,
			func(runID string, logger zerolog.Logger, h capture.Handle) error {
				return NewTCPSniffer(runID, logger, h, hops, nil).StartCapturing()
			},
			synAck(
				t,
				&net.TCPAddr{IP: server, Port: 443},
				&net.TCPAddr{IP: client, Port: 54321},
				52, 7000, 1001,
			),
		},
		{
			"udp", ProtoUDP, 1,
			func(runID string, logger zerolog.Logger, h capture.Handle) error {
				return NewUDPSniffer(runID, logger, h, hops).StartCapturing()
			},
			udpPacket(t, server, client, 52),
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			hops.Register(tc.proto, []net.IP{server})
			var logs lockedBuffer
			// Two packets: neither gets an ID of its own.
			h := &replayHandle{packets: [][]byte{tc.pkt.Data(), tc.pkt.Data()}}

			require.NoError(t, tc.start(runID, traceIDLogger(&logs), h))

			assert.Eventually(t, func() bool {
				return strings.Count(logs.String(), `"trace_id"`) == tc.logs
			}, time.Second, time.Millisecond)
			assert.Equal(t, tc.logs, strings.Count(logs.String(), `"trace_id":"`+runID+`"`))
		})
	}
}
