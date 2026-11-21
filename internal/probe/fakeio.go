package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/cache"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/desync"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/packet"
)

// gatewayResolveTimeout bounds the ARP lookup of the gateway's MAC address
// that fake packets are sent to, as in spoofdpi.
const gatewayResolveTimeout = 10 * time.Second

// errFakeCapture marks the failure to open the capture handle fake packets
// are sent with.
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

// packetFakes is the fake stack of spoofdpi's packet package.
type packetFakes struct {
	stack *packet.TCPStack
}

func (f packetFakes) desyncer(ttl uint8) (helloSender, *fakeLog) {
	log := &fakeLog{}
	return desync.NewTLSDesyncer(
		zerolog.Nop(),
		recordingWriter{TCPSeqWriter: f.stack.Writer, log: log},
		fixedTTLSniffer{Sniffer: f.stack.Sniffer, ttl: ttl},
		f.stack.Seqs,
	), log
}

// openFakeStack opens spoofdpi's packet stack on the interface of the
// default route, as spoofdpi does without --gateway, and registers servers
// with its sniffer, which then learns the sequence numbers of their
// connections. Like spoofdpi's, the stack stays open until the process
// exits.
func openFakeStack(ctx context.Context, servers []netip.Addr) (fakeStack, error) {
	route, err := netutil.DiscoverRoute(nil)
	if err != nil {
		return nil, err
	}
	resolveCtx, cancel := context.WithTimeout(ctx, gatewayResolveTimeout)
	defer cancel()
	gatewayMAC, err := packet.ResolveGatewayMAC(
		resolveCtx,
		&route.Iface,
		route.LocalIP,
		route.Gateway,
	)
	if err != nil {
		return nil, err
	}
	hopCache := cache.NewLRUCache[netutil.IPKey, packet.HopEntry](16, 8192, nil)
	stack, err := packet.OpenTCPStack(
		zerolog.Nop(),
		&route.Iface,
		gatewayMAC,
		hopCache,
		&config.RuntimeConfig{},
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errFakeCapture, err)
	}
	ips := make([]net.IP, len(servers))
	for i, s := range servers {
		ips[i] = s.AsSlice()
	}
	stack.Sniffer.Register(ips)
	return packetFakes{stack: stack}, nil
}

// fixedTTLSniffer is a sniffer whose fake packets leave with ttl, the TTL
// the probe chose from the actual hop count, rather than the one the
// sniffer learned.
type fixedTTLSniffer struct {
	packet.Sniffer
	ttl uint8
}

func (s fixedTTLSniffer) GetOptimalTTL(netutil.IPKey) uint8 { return s.ttl }

// LearnedHops reports no learned hop count, so that the desyncer sends the
// fake packets to a server whatever hop count it learned.
func (s fixedTTLSniffer) LearnedHops(netutil.IPKey) (uint8, bool) { return 0, false }

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
