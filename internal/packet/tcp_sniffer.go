package packet

import (
	"context"

	"github.com/google/gopacket"
	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/capture"
	"github.com/xvzc/spoofdpi/internal/logging"
	"github.com/xvzc/spoofdpi/internal/netutil"
)

var _ Sniffer = (*TCPSniffer)(nil)

type TCPSniffer struct {
	logger zerolog.Logger

	hops *HopStore
	seqs *SeqTracker

	handle capture.Handle
}

func NewTCPSniffer(
	logger zerolog.Logger,
	handle capture.Handle,
	hops *HopStore,
	seqs *SeqTracker,
) *TCPSniffer {
	return &TCPSniffer{
		logger: logger,
		handle: handle,
		hops:   hops,
		seqs:   seqs,
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
			ts.processPacket(
				logging.ContextWithTraceID(context.Background(), logging.NewTraceID()),
				packet,
			)
		}
	}()
}

// processPacket analyzes a single packet to find SYN/ACKs and store hop
// counts and the connection's sequence numbers.
func (ts *TCPSniffer) processPacket(ctx context.Context, p gopacket.Packet) {
	logger := logging.WithLocalScope(ctx, ts.logger, "sniff")

	sa, ok := capture.ParseSynAck(p)
	if !ok {
		return
	}

	nhops := sa.Hops

	// Only connections to registered servers are tracked: Learn decides
	// that, without re-inserting a server evicted meanwhile.
	prev, registered := ts.hops.Learn(ProtoTCP, sa.Src, nhops)
	if !registered {
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
			Str("from", netutil.NewIPKey(sa.Src).String()).
			Uint8("nhops", nhops).
			Uint8("ttlLeft", sa.TTLLeft).
			Msgf("ttl(tcp) update")
	}
}
