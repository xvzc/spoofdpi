package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/desync"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/packet"
	"github.com/xvzc/spoofdpi/internal/packetio/inject"
)

// errFakeCapture marks the failure to open the capture handle of the fake
// stack, or for lack of root the socket its fake packets are sent through.
var errFakeCapture = errors.New("open capture")

// fakeLog is what the fake packets of one attempt were.
type fakeLog struct {
	// sent is the number of fake packets sent.
	sent int
	// first is the header of the first one sent.
	first packet.TCPFake
	// pieces are the sequence numbers and payload lengths of those sent.
	pieces []fakePiece
	// err is the first error a fake packet failed with.
	err error
}

// fakePiece is the sequence numbers and payload length of a fake packet.
type fakePiece struct {
	packet.SeqAck
	length int
}

// fakeStack sends the fake packets of the fake and server checks; tests
// replace it.
type fakeStack interface {
	// desyncer returns spoofdpi's desyncer, sending its fake packets with
	// TTL ttl, and the log of the fake packets it sends.
	desyncer(ttl uint8) (helloSender, *fakeLog)
}

// openFakesFunc opens the fake stack, for connections to servers.
type openFakesFunc func(ctx context.Context, servers []netip.Addr) (fakeStack, error)

// packetFakes is the fake stack of spoofdpi's packet package, and the hop
// store its sniffer learns into.
type packetFakes struct {
	stack *packet.TCPStack
	hops  *packet.HopStore
}

func (f packetFakes) desyncer(ttl uint8) (helloSender, *fakeLog) {
	log := &fakeLog{}
	return desync.NewTLSDesyncer(
		zerolog.Nop(),
		recordingWriter{
			TCPSeqWriter: fixedTTLWriter{TCPSeqWriter: f.stack.Writer, ttl: ttl},
			log:          log,
		},
		unlearnedHops{HopReader: f.hops},
		f.stack.Seqs,
		nil,
	), log
}

// openFakeStack opens spoofdpi's packet stack on the interface of the
// default route, as spoofdpi does without --gateway, and registers servers
// for TCP hop-count learning, so that its sniffer learns the sequence
// numbers of their connections. Like spoofdpi's, the stack stays open until the process
// exits.
func openFakeStack(ctx context.Context, servers []netip.Addr) (fakeStack, error) {
	iface, _, err := netutil.DiscoverInterface()
	if err != nil {
		return nil, err
	}
	sender, err := packet.OpenIPv4Sender(ctx, zerolog.Nop(), inject.Options{})
	if errors.Is(err, inject.ErrNeedsRoot) {
		return nil, fmt.Errorf("%w: %w", errFakeCapture, err)
	}
	if err != nil {
		return nil, err
	}
	hops := packet.NewHopStore()
	stack, err := packet.OpenTCPStack(
		"",
		zerolog.Nop(),
		iface,
		packet.Senders{V4: sender},
		hops,
	)
	if err != nil {
		_ = sender.Close()
		return nil, fmt.Errorf("%w: %w", errFakeCapture, err)
	}
	ips := make([]net.IP, len(servers))
	for i, s := range servers {
		ips[i] = s.AsSlice()
	}
	hops.Register(packet.ProtoTCP, ips)
	return packetFakes{stack: stack, hops: hops}, nil
}

// unlearnedHops is a hop reader that reports no learned hop count for any
// server, so that the desyncer sends the fake packets to a server whatever
// hop count the sniffer learned, even one on the local link.
type unlearnedHops struct {
	packet.HopReader
}

func (unlearnedHops) Lookup(packet.Proto, net.IP) packet.HopEstimate {
	return packet.HopEstimate{Source: packet.HopSourceDefault}
}

// fixedTTLWriter is a writer whose fake packets leave with ttl, the TTL
// the probe chose from the actual hop count, rather than the one the
// desyncer computed from the sniffer's hop count.
type fixedTTLWriter struct {
	packet.TCPSeqWriter
	ttl uint8
}

func (w fixedTTLWriter) WriteCraftedPacketWithSeq(
	ctx context.Context,
	src net.Addr,
	dst net.Addr,
	_ uint8,
	payload []byte,
	fake packet.TCPFake,
) (int, error) {
	return w.TCPSeqWriter.WriteCraftedPacketWithSeq(ctx, src, dst, w.ttl, payload, fake)
}

// recordingWriter is a writer that records the fake packets it sends in
// log: the desyncer goes on with the real ClientHello when they fail.
type recordingWriter struct {
	packet.TCPSeqWriter
	log *fakeLog
}

func (w recordingWriter) WriteCraftedPacketWithSeq(
	ctx context.Context,
	src net.Addr,
	dst net.Addr,
	ttl uint8,
	payload []byte,
	fake packet.TCPFake,
) (int, error) {
	n, err := w.TCPSeqWriter.WriteCraftedPacketWithSeq(ctx, src, dst, ttl, payload, fake)
	if err != nil {
		if w.log.err == nil {
			w.log.err = err
		}
		return n, err
	}
	if w.log.sent == 0 {
		w.log.first = fake
	}
	w.log.sent++
	w.log.pieces = append(
		w.log.pieces,
		fakePiece{SeqAck: fake.SeqAck, length: len(payload)},
	)
	return n, nil
}
