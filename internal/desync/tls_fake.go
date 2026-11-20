package desync

import (
	"context"
	"net"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/packet"
)

// fakeSender sends the fake packets of one connection: the copies of the
// fake Client Hello sent before the real one (preflight), and the fake
// segments sent before each real segment (stutter).
//
// Every fake carries the real sequence numbers of the bytes it covers,
// plus fake-seq-offset and fake-ack-offset.
type fakeSender struct {
	writer    packet.TCPSeqWriter
	conn      net.Conn
	ttl       uint8
	opts      *config.HTTPSOptions
	realStart packet.SeqAck
	fakeStart packet.SeqAck

	// mss is the largest payload of one fake packet: the connection's MSS,
	// so that fakes are split where the kernel splits the real data and no
	// fake exceeds the path MTU.
	mss int
}

// fallbackMSS is used when the connection's MSS cannot be read. It is low
// enough for paths with a reduced MTU, such as VPNs and PPPoE.
const fallbackMSS = 1200

// connMSS returns conn's MSS, or fallbackMSS if it cannot be read.
func connMSS(conn net.Conn) int {
	mss, err := netutil.MSS(conn)
	if err != nil || mss <= 0 {
		return fallbackMSS
	}
	return mss
}

func newFakeSender(
	writer packet.TCPSeqWriter,
	conn net.Conn,
	ttl uint8,
	opts *config.HTTPSOptions,
	real packet.SeqAck,
) *fakeSender {
	return &fakeSender{
		writer:    writer,
		conn:      conn,
		ttl:       ttl,
		opts:      opts,
		realStart: real,
		fakeStart: fakeSeqAck(real, opts),
		mss:       connMSS(conn),
	}
}

// write sends payload as fake packets starting at sa, split into pieces of
// at most f.mss bytes with consecutive sequence numbers.
func (f *fakeSender) write(
	ctx context.Context,
	payload []byte,
	sa packet.SeqAck,
) (int, error) {
	var total int
	for len(payload) > 0 {
		piece := payload[:min(len(payload), f.mss)]
		n, err := f.writer.WriteCraftedPacketWithSeq(
			ctx,
			f.conn.LocalAddr(),
			f.conn.RemoteAddr(),
			f.ttl,
			piece,
			sa,
		)
		total += n
		if err != nil {
			return total, err
		}
		sa.Seq += uint32(len(piece))
		payload = payload[len(piece):]
	}

	return total, nil
}

// preflight sends opts.FakePreflight copies of the fake Client Hello, each
// split like the real one and starting where the real one starts. Fakes do
// not consume the connection's sequence space.
func (f *fakeSender) preflight(
	ctx context.Context,
	logger zerolog.Logger,
) (int, error) {
	var total int
	segments := split(logger, f.opts.FakePacket, f.opts)

	for range f.opts.FakePreflight {
		cur := f.fakeStart
		for _, v := range segments {
			n, err := f.write(ctx, v.Packet, cur)
			total += n
			if err != nil {
				return total, err
			}
			cur.Seq += uint32(len(v.Packet))
		}
	}

	return total, nil
}

// stutter sends opts.FakeStutter fake segments covering the same bytes as
// the real segment that starts at real and spans [offset, offset+length)
// of the Client Hello. Their content is the fake Client Hello's bytes at
// that range, padded with zeros past its end.
func (f *fakeSender) stutter(
	ctx context.Context,
	real packet.SeqAck,
	offset, length int,
) (int, error) {
	payload := fakeRange(f.opts.FakePacket.Raw(), offset, length)
	sa := fakeSeqAck(real, f.opts)

	var total int
	for range f.opts.FakeStutter {
		n, err := f.write(ctx, payload, sa)
		if err != nil {
			return total, err
		}
		total += n
	}

	return total, nil
}

// fakeRange returns length bytes of fake starting at offset, padded with
// zeros where fake is shorter.
func fakeRange(fake []byte, offset, length int) []byte {
	out := make([]byte, length)
	if offset < len(fake) {
		copy(out, fake[offset:min(offset+length, len(fake))])
	}
	return out
}
