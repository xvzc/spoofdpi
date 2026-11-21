package packet

import (
	"context"
	"net"

	"github.com/google/gopacket"
	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/cache"
	"github.com/xvzc/spoofdpi/internal/capture"
	"github.com/xvzc/spoofdpi/internal/logging"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/session"
)

var _ Sniffer = (*TCPSniffer)(nil)

type TCPSniffer struct {
	logger zerolog.Logger

	nhopCache cache.Cache[netutil.IPKey, HopEntry]
	seqs      *SeqTracker

	handle capture.Handle
}

func NewTCPSniffer(
	logger zerolog.Logger,
	handle capture.Handle,
	cache cache.Cache[netutil.IPKey, HopEntry],
	seqs *SeqTracker,
) *TCPSniffer {
	return &TCPSniffer{
		logger:    logger,
		handle:    handle,
		nhopCache: cache,
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
			HopEntry{},
			cache.Options().WithSkipExisting(true),
		)
	}
}

// Hops returns the hop-count cache entry of key, and whether key is cached.
func (ts *TCPSniffer) Hops(key netutil.IPKey) (HopEntry, bool) {
	return ts.nhopCache.Get(key)
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

	// prev only feeds the trace log below. The update-only Set decides
	// whether key is registered, so a key evicted after this Get is not
	// re-inserted.
	prev, _ := ts.nhopCache.Get(key)
	if !ts.nhopCache.Set(
		key,
		HopEntry{Hops: nhops, Learned: true},
		cache.Options().WithUpdateExistingOnly(true),
	) {
		return
	}

	// The SYN/ACK's Ack is the client's next sequence number, and the
	// client acknowledges the server's SYN with Seq+1.
	if ts.seqs != nil {
		ts.seqs.Put(
			netutil.NewNATKey(sa.Dst, int(sa.DstPort), sa.Src, int(sa.SrcPort)),
			SeqAck{Seq: sa.Ack, Ack: sa.Seq + 1},
		)
	}
	if !prev.Learned || nhops != prev.Hops {
		logger.Trace().
			Str("from", key.String()).
			Uint8("nhops", nhops).
			Uint8("ttlLeft", sa.TTLLeft).
			Msgf("ttl(tcp) update")
	}
}
