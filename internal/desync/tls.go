package desync

import (
	"cmp"
	"context"
	"fmt"
	"math/bits"
	"math/rand/v2"
	"net"
	"slices"

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
	writer  packet.Writer
	sniffer packet.Sniffer
}

func NewTLSDesyncer(
	writer packet.Writer, sniffer packet.Sniffer,
) *TLSDesyncer {
	return &TLSDesyncer{
		writer:  writer,
		sniffer: sniffer,
	}
}

func (d *TLSDesyncer) Desync(
	ctx context.Context,
	logger zerolog.Logger,
	conn net.Conn,
	msg *proto.TLSMessage,
	httpsOpts *config.HTTPSOptions,
) (int, error) {
	logger = logging.WithLocalScope(ctx, logger, "tls_desync")

	if httpsOpts.Skip {
		logger.Trace().Msg("skip desync for this request")
		return d.sendSegments(conn, logger, []Segment{{Packet: msg.Raw()}})
	}

	if d.sniffer != nil && d.writer != nil && httpsOpts.FakeCount > 0 {
		oTTL := d.sniffer.GetOptimalTTL(
			netutil.NewIPKey(conn.RemoteAddr().(*net.TCPAddr).IP),
		)
		n, err := d.sendFakePackets(ctx, logger, conn, oTTL, httpsOpts)
		if err != nil {
			logger.Warn().Err(err).Msg("failed to send fake packets")
		} else {
			logger.Debug().Int("len", n).Uint8("ttl", oTTL).Msg("sent fake packets")
		}
	}

	segments := split(logger, msg, httpsOpts)

	return d.sendSegments(conn, logger, segments)
}

// sendSegments sends the segmented Client Hello sequentially.
func (d *TLSDesyncer) sendSegments(
	conn net.Conn,
	logger zerolog.Logger,
	segments []Segment,
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

	total := 0
	for _, chunk := range segments {
		if !ttlErrored && chunk.Lazy {
			setTTLWrap(1)
		}

		n, err := conn.Write(chunk.Packet)
		total += n
		if err != nil {
			return total, err
		}

		if !ttlErrored && chunk.Lazy {
			setTTLWrap(defaultTTL)
		}
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
		segments, err = applySegmentPlans(msg, opts.CustomSegmentPlans)
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

func (d *TLSDesyncer) sendFakePackets(
	ctx context.Context,
	logger zerolog.Logger,
	conn net.Conn,
	oTTL uint8,
	opts *config.HTTPSOptions,
) (int, error) {
	var totalSent int
	segments := split(logger, opts.FakePacket, opts)

	for range opts.FakeCount {
		for _, v := range segments {
			n, err := d.writer.WriteCraftedPacket(
				ctx,
				conn.LocalAddr(),
				conn.RemoteAddr(),
				oTTL,
				v.Packet,
			)
			if err != nil {
				return totalSent, err
			}

			totalSent += n
		}
	}

	return totalSent, nil
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
