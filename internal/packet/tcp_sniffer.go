package packet

import (
	"context"
	"net"

	"github.com/google/gopacket"
	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/cache"
	"github.com/xvzc/spoofdpi/internal/capture"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/logging"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/session"
)

var _ Sniffer = (*TCPSniffer)(nil)

type TCPSniffer struct {
	logger zerolog.Logger

	nhopCache cache.Cache[netutil.IPKey, HopEntry]
	hops      HopPolicy
	seqs      *SeqTracker

	handle capture.Handle
}

func NewTCPSniffer(
	logger zerolog.Logger,
	handle capture.Handle,
	cache cache.Cache[netutil.IPKey, HopEntry],
	seqs *SeqTracker,
	cfg *config.RuntimeConfig,
) *TCPSniffer {
	return &TCPSniffer{
		logger:    logger,
		handle:    handle,
		nhopCache: cache,
		hops:      NewHopPolicy(cfg.Conn),
		seqs:      seqs,
	}
}

// StartCapturing begins monitoring for SYN/ACK packets in a background goroutine.
func (ts *TCPSniffer) StartCapturing() {
	_ = ts.handle.ClearBPF()
	_ = ts.handle.SetBPFRawInstructionFilter(capture.SynAckFilter(ts.handle.LinkType()))

	packetSource := gopacket.NewPacketSource(ts.handle, ts.handle.LinkType())
	packets := packetSource.Packets()

	go func() {
		for packet := range packets {
			ts.processPacket(session.WithNewTraceID(context.Background()), packet)
		}
	}()
}

// Register registers new IP addresses for hop-count learning.
// Addresses that are already being tracked are ignored.
func (ts *TCPSniffer) Register(addrs []net.IP) {
	for _, v := range addrs {
		ts.nhopCache.Set(
			netutil.NewIPKey(v),
			HopEntry{Hops: ts.hops.Default, Learned: false},
			cache.Options().WithSkipExisting(true),
		)
	}
}

// GetOptimalTTL retrieves the estimated hop count for a given key from the cache.
func (ts *TCPSniffer) GetOptimalTTL(key netutil.IPKey) uint8 {
	e, ok := ts.nhopCache.Get(key)
	return ts.hops.TTL(e, ok)
}

// LearnedHops returns the hop count for key and whether it was learned
// from a captured packet.
func (ts *TCPSniffer) LearnedHops(key netutil.IPKey) (uint8, bool) {
	e, ok := ts.nhopCache.Get(key)
	if !ok || !e.Learned {
		return 0, false
	}
	return e.Hops, true
}

// processPacket analyzes a single packet to find SYN/ACKs and store hop
// counts and the connection's sequence numbers.
func (ts *TCPSniffer) processPacket(ctx context.Context, p gopacket.Packet) {
	logger := logging.WithLocalScope(ctx, ts.logger, "sniff")

	sa, ok := capture.ParseSynAck(p)
	if !ok {
		return
	}

	key := netutil.NewIPKey(sa.Src)
	nhops := sa.Hops

	prev, exists := ts.nhopCache.Get(key)
	if !exists {
		return
	}

	ts.nhopCache.Set(key, HopEntry{Hops: nhops, Learned: true}, nil)

	// The SYN/ACK's Ack is the client's next sequence number, and the
	// client acknowledges the server's SYN with Seq+1.
	if ts.seqs != nil {
		ts.seqs.Put(
			netutil.NewNATKey(sa.Dst, int(sa.DstPort), sa.Src, int(sa.SrcPort)),
			SeqAck{Seq: sa.Ack, Ack: sa.Seq + 1},
		)
	}
	if nhops != prev.Hops {
		logger.Trace().
			Str("from", key.String()).
			Uint8("nhops", nhops).
			Uint8("ttlLeft", sa.TTLLeft).
			Msgf("ttl(tcp) update")
	}
}
