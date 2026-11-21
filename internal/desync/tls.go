package desync

import (
	"cmp"
	"context"
	"fmt"
	"math/bits"
	"math/rand/v2"
	"net"
	"slices"
	"time"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/logging"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/packet"
	"github.com/xvzc/spoofdpi/internal/proto"
)

type Segment struct {
	Packet []byte
	Lazy   bool
}

// TLSDesyncer splits the data into chunks and optionally
// disorders packets by manipulating TTL.
type TLSDesyncer struct {
	logger  zerolog.Logger
	writer  packet.TCPSeqWriter
	sniffer packet.Sniffer
	seqs    *packet.SeqTracker
}

func NewTLSDesyncer(
	logger zerolog.Logger,
	writer packet.TCPSeqWriter,
	sniffer packet.Sniffer,
	seqs *packet.SeqTracker,
) *TLSDesyncer {
	return &TLSDesyncer{logger: logger, writer: writer, sniffer: sniffer, seqs: seqs}
}

// PrepareHopTrack registers addrs with the sniffer for hop-count learning,
// guarded by the config so the LRU isn't touched when fakes won't be sent.
func (d *TLSDesyncer) PrepareHopTrack(addrs []net.IP, cfg *config.HTTPSOptions) {
	if d.sniffer == nil || cfg.Skip || !cfg.UsesFakes() {
		return
	}
	d.sniffer.Register(addrs)
}

func (d *TLSDesyncer) Desync(
	ctx context.Context,
	conn net.Conn,
	msg *proto.TLSMessage,
	httpsOpts *config.HTTPSOptions,
	connOpts *config.ConnOptions,
) (int, error) {
	logger := logging.WithLocalScope(ctx, d.logger, "tls_desync")

	if httpsOpts.Skip {
		logger.Trace().Msg("skip desync for this request")
		return d.sendSegments(ctx, conn, logger, []Segment{{Packet: msg.Raw()}}, nil, nil)
	}

	// seq tracks the connection's next sequence number while segments are
	// sent; fakes sends the fake packets. Both are nil when no fake packets
	// are sent.
	var seq *packet.SeqAck
	var fakes *fakeSender
	if httpsOpts.UsesFakes() && d.sniffer != nil && d.writer != nil {
		// Wait for the SYN/ACK first: the sniffer learns the hop count from
		// it too, so the TTL read after it is fresher.
		real := d.learnSeqAck(ctx, logger, conn, httpsOpts)
		key := netutil.NewIPKey(conn.RemoteAddr().(*net.TCPAddr).IP)
		if onLocalLink(d.sniffer, key) {
			logger.Debug().Msg("server is on the local link, skipping fake packets")
			return d.sendSegments(ctx, conn, logger, split(logger, msg, httpsOpts), nil, nil)
		}
		seq = &real
		oTTL := fakeTTL(d.sniffer, key, connOpts)
		fakes = newFakeSender(d.writer, conn, oTTL, httpsOpts, real)
		logger.Trace().
			Uint32("seq", fakes.fakeStart.Seq).
			Uint32("ack", fakes.fakeStart.Ack).
			Int64("seq_offset", httpsOpts.FakeSeqOffset).
			Int64("ack_offset", httpsOpts.FakeAckOffset).
			Msg("fake sequence numbers")
		if httpsOpts.FakePreflight > 0 {
			n, err := fakes.preflight(ctx, logger)
			if err != nil {
				logger.Warn().Err(err).Msg("failed to send fake packets")
			} else {
				logger.Debug().Int("len", n).Uint8("ttl", oTTL).Msg("sent fake packets")
			}
		}
	}

	segments := split(logger, msg, httpsOpts)

	return d.sendSegments(ctx, conn, logger, segments, seq, fakes)
}

// learnSeqAck returns the connection's next sequence numbers, learned
// from its SYN/ACK. If they are not learned, it returns random ones chosen
// once for the connection, so that the segments of each fake still line up.
//
// For IPv4 servers, it waits up to opts.SynAckTimeout for the sniffer to
// process the SYN/ACK. IPv6 servers are not learned, so it does not wait.
func (d *TLSDesyncer) learnSeqAck(
	ctx context.Context,
	logger zerolog.Logger,
	conn net.Conn,
	opts *config.HTTPSOptions,
) packet.SeqAck {
	random := packet.SeqAck{Seq: rand.Uint32(), Ack: rand.Uint32()}

	local, lok := conn.LocalAddr().(*net.TCPAddr)
	remote, rok := conn.RemoteAddr().(*net.TCPAddr)
	if d.seqs == nil || !lok || !rok || !packet.CanLearnSeq(remote.IP) {
		return random
	}

	start := time.Now()
	sa, ok := d.seqs.Wait(ctx, packet.SeqKey(local, remote), opts.SynAckTimeout)
	logger.Trace().
		Bool("learned", ok).
		Dur("waited", time.Since(start)).
		Msg("waited for syn/ack")
	if !ok {
		return random
	}

	return sa
}

// onLocalLink reports whether the server at key is known to be on the local
// link (0 hops). No TTL can stop a fake packet before such a server, and no
// DPI can sit in between, so fakes are pointless and only risk the
// connection.
func onLocalLink(sniffer packet.Sniffer, key netutil.IPKey) bool {
	e, ok := sniffer.Hops(key)
	return ok && e.Learned && e.Hops == 0
}

// fakeTTL returns the TTL of fake packets to the server at key, from the
// hop count the sniffer cached for it and the hop-count options of the
// connection, which a matched rule may override.
func fakeTTL(sniffer packet.Sniffer, key netutil.IPKey, o *config.ConnOptions) uint8 {
	e, ok := sniffer.Hops(key)
	policy := packet.HopPolicy{
		Default: o.HopCountDefault,
		Min:     o.HopCountMin,
		Max:     o.HopCountMax,
		Offset:  o.HopCountOffset,
	}
	return policy.TTL(e, ok)
}

// fakeSeqAck adds opts.FakeSeqOffset and opts.FakeAckOffset to the
// connection's real sequence numbers. The uint32 conversion of a negative
// offset wraps, which is what we want (mod 2^32).
func fakeSeqAck(real packet.SeqAck, opts *config.HTTPSOptions) packet.SeqAck {
	return packet.SeqAck{
		Seq: real.Seq + uint32(opts.FakeSeqOffset),
		Ack: real.Ack + uint32(opts.FakeAckOffset),
	}
}

// sendSegments sends the segmented Client Hello sequentially. If seq is not
// nil, it is advanced by every byte written so that it always holds the
// connection's next sequence number. If fakes is not nil and stutter is
// enabled, the fake segments for each segment are sent right before it.
func (d *TLSDesyncer) sendSegments(
	ctx context.Context,
	conn net.Conn,
	logger zerolog.Logger,
	segments []Segment,
	seq *packet.SeqAck,
	fakes *fakeSender,
) (int, error) {
	var isIPv4 bool
	if tcpAddr, ok := conn.LocalAddr().(*net.TCPAddr); ok {
		isIPv4 = tcpAddr.IP.To4() != nil
	}

	var ttlErrored bool
	setTTLWrap := func(ttl uint8) {
		if err := netutil.SetTTL(conn, isIPv4, ttl); err != nil {
			logger.Warn().Err(err).Msg("failed to set TTL, continuing without modifying ttl")
			ttlErrored = true
		}
	}

	defaultTTL := getDefaultTTL()
	stuttering := fakes != nil && seq != nil && fakes.opts.FakeStutter > 0

	total, offset, stuttered := 0, 0, 0
	var stutterErr error
	for _, chunk := range segments {
		if stuttering && stutterErr == nil {
			n, err := fakes.stutter(ctx, *seq, offset, len(chunk.Packet))
			stuttered += n
			stutterErr = err
		}

		if !ttlErrored && chunk.Lazy {
			setTTLWrap(1)
		}

		n, err := conn.Write(chunk.Packet)
		total += n
		offset += n
		if seq != nil {
			seq.Seq += uint32(n)
		}
		if err != nil {
			return total, err
		}

		if !ttlErrored && chunk.Lazy {
			setTTLWrap(defaultTTL)
		}
	}

	if stutterErr != nil {
		logger.Warn().Err(stutterErr).Msg("failed to send stutter fakes")
	} else if stuttering {
		logger.Debug().
			Int("len", stuttered).
			Int("segments", len(segments)).
			Msg("sent stutter fakes")
	}

	return total, nil
}

func split(
	logger zerolog.Logger,
	msg *proto.TLSMessage,
	opts *config.HTTPSOptions,
) []Segment {
	mode := opts.SplitMode
	raw := msg.Raw()
	var segments []Segment
	var err error
	switch mode {
	case config.HTTPSSplitModeSNI:
		var start, end int
		start, end, err = msg.ExtractSNIOffset()
		if err != nil {
			break
		}
		segments, err = splitSNI(raw, start, end, opts.Disorder)
		logger.Trace().Msgf("extracted SNI is '%s'", raw[start:end])
	case config.HTTPSSplitModeRandom:
		mask := genPatternMask()
		segments, err = splitMask(raw, mask, opts.Disorder)
	case config.HTTPSSplitModeChunk:
		segments, err = splitChunks(raw, int(opts.ChunkSize), opts.Disorder)
	case config.HTTPSSplitModeFirstByte:
		segments, err = splitFirstByte(raw, opts.Disorder)
	case config.HTTPSSplitModeCustom:
		segments, err = applySegmentPlans(msg, opts.CustomSplit)
	case config.HTTPSSplitModeNone:
		segments = []Segment{{Packet: raw}}
	default:
		logger.Debug().Msgf("unsupprted split mode '%s'. proceed without split", mode)
		segments = []Segment{{Packet: raw}}
	}

	logger.Debug().
		Int("len", len(segments)).
		Str("mode", mode.String()).
		Str("kind", msg.Kind()).
		Bool("disorder", opts.Disorder).
		Msg("segments ready")

	if err != nil {
		logger.Debug().Err(err).
			Str("kind", msg.Kind()).
			Msgf("error processing split mode '%s', fallback to 'none'", mode)
		segments = []Segment{{Packet: raw}}
	}

	return segments
}

func splitChunks(raw []byte, size int, disorder bool) ([]Segment, error) {
	lenRaw := len(raw)

	if lenRaw == 0 {
		return nil, fmt.Errorf("empty data")
	}

	if size == 0 {
		return nil, fmt.Errorf("size == 0")
	}

	capacity := (lenRaw + size - 1) / size
	chunks := make([]Segment, 0, capacity)

	curDisorder := true
	for len(raw) > 0 {
		n := min(len(raw), size)
		chunks = append(chunks, Segment{Packet: raw[:n], Lazy: curDisorder && disorder})
		raw = raw[n:]
		curDisorder = !curDisorder
	}

	return chunks, nil
}

func splitFirstByte(raw []byte, disorder bool) ([]Segment, error) {
	if len(raw) < 2 {
		return nil, fmt.Errorf("len(raw) is less than 2")
	}

	return []Segment{
		{Packet: raw[:1], Lazy: disorder && true},
		{Packet: raw[1:], Lazy: false},
	}, nil
}

func splitSNI(raw []byte, start, end int, disorder bool) ([]Segment, error) {
	lenRaw := len(raw)

	if lenRaw == 0 {
		return nil, fmt.Errorf("empty data")
	}

	if start > end {
		return nil, fmt.Errorf("invalid start, end pos (start > end)")
	}

	if start < 0 || lenRaw <= start || end < 0 || lenRaw <= end {
		return nil, fmt.Errorf("invalid start, end pos (out of range)")
	}

	curDisorder := true
	segments := make([]Segment, 0, lenRaw)
	segments = append(segments, Segment{Packet: raw[:start]})
	for i := range end - start {
		segments = append(segments, Segment{
			Packet: []byte{raw[start+i]},
			Lazy:   curDisorder && disorder,
		})
		curDisorder = !curDisorder
	}

	segments = append(segments, Segment{
		Packet: raw[end:],
		Lazy:   curDisorder && disorder,
	})

	return segments, nil
}

func splitMask(raw []byte, mask uint64, disorder bool) ([]Segment, error) {
	lenRaw := len(raw)

	if lenRaw == 0 {
		return nil, fmt.Errorf("empty data")
	}

	curDisorder := true
	segments := make([]Segment, 0, lenRaw)
	start := 0
	curBit := uint64(1)
	for i := range lenRaw {
		if mask&curBit == curBit {
			if i > start {
				segments = append(segments, Segment{
					Packet: raw[start:i],
					Lazy:   curDisorder && disorder,
				})
				curDisorder = !curDisorder
			}

			segments = append(segments, Segment{
				Packet: raw[i : i+1],
				Lazy:   curDisorder && disorder,
			})

			start = i + 1
			curDisorder = !curDisorder
		}

		curBit = bits.RotateLeft64(curBit, 1)
	}

	if lenRaw > start {
		segments = append(segments, Segment{
			Packet: raw[start:lenRaw],
			Lazy:   curDisorder && disorder,
		})
	}

	return segments, nil
}

func (d *TLSDesyncer) String() string {
	return "split"
}

func applySegmentPlans(
	msg *proto.TLSMessage,
	plans []config.SegmentPlan,
) ([]Segment, error) {
	raw := msg.Raw()
	sniStart, _, err := msg.ExtractSNIOffset()
	if err != nil {
		return nil, err
	}

	type splitPoint struct {
		at   int
		lazy bool
	}

	points := make([]splitPoint, 0, len(plans))
	for _, s := range plans {
		base := 0
		if s.From == config.SegmentFromSNI {
			base = sniStart
		}

		at := base + s.At
		if s.Noise > 0 {
			at += rand.IntN(s.Noise*2+1) - s.Noise
		}
		at = max(0, min(at, len(raw)))

		points = append(points, splitPoint{at: at, lazy: s.Lazy})
	}

	slices.SortFunc(points, func(a, b splitPoint) int {
		return cmp.Compare(a.at, b.at)
	})

	var segments []Segment
	prvAt := 0
	for _, p := range points {
		if p.at == prvAt {
			continue
		}
		segments = append(segments, Segment{
			Packet: raw[prvAt:p.at],
			Lazy:   p.lazy,
		})
		prvAt = p.at
	}

	if prvAt < len(raw) {
		segments = append(segments, Segment{Packet: raw[prvAt:]})
	}

	return segments, nil
}

func getDefaultTTL() uint8 {
	return 64
}

// --- Helper Functions (Low-level Syscall) ---

// genPatternMask generates a pseudo-random 64-bit mask used for determining
// split points or disorder indices in the packet fragmentation process.
//
// Instead of relying on slow modulo operations or heavy PRNG calls,
// it utilizes a lightweight Xorshift algorithm to mutate the seed for each byte.
// This ensures a high-performance, non-deterministic pattern distribution
// where at least one bit is set in every 8-bit block.
func genPatternMask() uint64 {
	// Initialize the seed using the default PRNG.
	// This is called once per generation, so the cost is negligible.
	seed := rand.Uint()

	var ret uint64 = 0

	// Block 0 [0-7 bits]:
	// Ensure LSB is always 1 to guarantee at least one operation at the start.
	// The second bit is placed randomly within the remaining 7 bits.
	ret |= uint64(0b10101001)

	// Block 1 [8-15 bits]:
	// Place 2 bits randomly within this byte using the mutated seed.
	seed ^= (seed >> 13)
	ret |= uint64(bits.RotateLeft8(0b10000000, int(seed))) << 8
	seed ^= (seed << 11)
	ret |= uint64(bits.RotateLeft8(0b10000000, -int(seed%7)+1)) << 8

	// Block 2 [16-23 bits]:
	seed ^= (seed >> 17)
	ret |= uint64(bits.RotateLeft8(0b00000001, int(seed))) << 16
	// ret |= uint64(0b00000001) << 16
	// ret |= uint64(bits.RotateLeft8(0b00000001, int(seed%3)+2)) << 16
	// ret |= uint64(bits.RotateLeft8(0b00000001, int(seed%4)+4)) << 16

	// Block 3 [24-31 bits]:
	seed ^= (seed << 5)
	ret |= uint64(bits.RotateLeft8(0b00000001, int(seed))) << 24

	// Block 4 [32-39 bits]:
	seed ^= (seed >> 12)
	// ret |= uint64(bits.RotateLeft8(0b00000001, int(seed))) << 32
	ret |= uint64(bits.RotateLeft8(0b00000001, int(seed%2))) << 32
	ret |= uint64(bits.RotateLeft8(0b00000001, int(seed%3)+2)) << 32
	ret |= uint64(bits.RotateLeft8(0b00000001, int(seed%3)+5)) << 32

	// Block 5 [40-47 bits]:
	seed ^= (seed << 25)
	ret |= uint64(bits.RotateLeft8(0b00000001, int(seed))) << 40

	// Block 6 [48-55 bits]:
	seed ^= (seed >> 27)
	ret |= uint64(bits.RotateLeft8(0b00000001, int(seed))) << 48

	// Block 7 [56-63 bits]:
	seed ^= (seed << 13)
	ret |= uint64(bits.RotateLeft8(0b00000001, int(seed))) << 56

	return ret
}
