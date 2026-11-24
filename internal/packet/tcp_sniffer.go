package packet

import (
	"context"
	"fmt"

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

// StartCapturing begins monitoring for SYN/ACK packets in a background
// goroutine. It returns an error if the SYN/ACK filter cannot be built, in
// which case it wraps capture.ErrUnsupportedLinkType for a link type the
// filter does not support, or installed.
func (ts *TCPSniffer) StartCapturing() error {
	// Detaching fails on a Linux socket that has no filter yet (ENOENT),
	// and attaching a filter replaces any previous one, so a failed clear
	// is harmless.
	_ = ts.handle.ClearBPF()
	filter, err := capture.SynAckFilter(ts.handle.LinkType())
	if err != nil {
		return fmt.Errorf("build SYN/ACK capture filter: %w", err)
	}
	if err := ts.handle.SetBPFRawInstructionFilter(filter); err != nil {
		return fmt.Errorf("set SYN/ACK capture filter: %w", err)
	}

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

	return nil
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
		logger.Trace().
			Str("from", joinAddrPort(sa.Src, sa.SrcPort)).
			Str("to", joinAddrPort(sa.Dst, sa.DstPort)).
			Uint8("nhops", nhops).
			Uint8("ttlLeft", sa.TTLLeft).
			Msgf("ttl(tcp) ignored, destination not registered")
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

	// The ports tie the line to a connection: to is the local address of
	// the socket spoofdpi dialed, which its "new remote conn" log shows.
	event := logger.Trace().
		Str("from", joinAddrPort(sa.Src, sa.SrcPort)).
		Str("to", joinAddrPort(sa.Dst, sa.DstPort)).
		Uint8("nhops", nhops).
		Uint8("ttlLeft", sa.TTLLeft)
	if !prev.Learned || nhops != prev.Hops {
		event.Msgf("ttl(tcp) update")
		return
	}
	event.Msgf("ttl(tcp) unchanged")
}
