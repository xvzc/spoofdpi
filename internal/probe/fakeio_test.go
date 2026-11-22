package probe

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/desync"
	"github.com/xvzc/spoofdpi/internal/packet"
)

// stubHops is a hop reader that has learned a hop count of 0 for every
// server, which makes spoofdpi's desyncer skip the fakes.
type stubHops struct {
	registered []net.IP
}

func (s *stubHops) Register(_ packet.Proto, addrs []net.IP) {
	s.registered = append(s.registered, addrs...)
}

func (s *stubHops) Lookup(packet.Proto, net.IP) packet.HopEstimate {
	return packet.HopEstimate{Hops: 0, Source: packet.HopSourceLearned}
}

// sentFake is a fake packet a stubWriter was asked to send.
type sentFake struct {
	ttl     uint8
	payload []byte
	fake    packet.TCPFake
}

// stubWriter records the fake packets it is asked to send, and fails them
// with err.
type stubWriter struct {
	mu   sync.Mutex
	sent []sentFake
	err  error
}

func (w *stubWriter) WriteCraftedPacket(
	context.Context, net.Addr, net.Addr, uint8, []byte,
) (int, error) {
	return 0, errors.New("not used")
}

func (w *stubWriter) WriteCraftedPacketWithSeq(
	_ context.Context,
	_, _ net.Addr,
	ttl uint8,
	payload []byte,
	fake packet.TCPFake,
) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return 0, w.err
	}
	w.sent = append(w.sent, sentFake{ttl: ttl, payload: payload, fake: fake})
	return len(payload), nil
}

func TestUnlearnedHops(t *testing.T) {
	inner := &stubHops{}
	h := unlearnedHops{HopReader: inner}
	est := h.Lookup(packet.ProtoTCP, net.IPv4(203, 0, 113, 1))
	assert.Equal(
		t,
		packet.HopEstimate{Source: packet.HopSourceDefault},
		est,
		"the desyncer must not skip the fakes",
	)
	h.Register(packet.ProtoTCP, []net.IP{net.IPv4(203, 0, 113, 1)})
	assert.Len(t, inner.registered, 1, "registration reaches the store")
}

func TestFixedTTLWriter(t *testing.T) {
	w := &stubWriter{}
	fw := fixedTTLWriter{TCPSeqWriter: w, ttl: 9}
	fake := packet.TCPFake{SeqAck: packet.SeqAck{Seq: 1, Ack: 2}}
	_, err := fw.WriteCraftedPacketWithSeq(
		context.Background(), nil, nil, 3, []byte("a"), fake,
	)
	require.NoError(t, err)
	assert.Equal(t, []sentFake{{ttl: 9, payload: []byte("a"), fake: fake}}, w.sent)
}

func TestRecordingWriter(t *testing.T) {
	w := &stubWriter{}
	log := &fakeLog{}
	rw := recordingWriter{TCPSeqWriter: w, log: log}
	first := packet.TCPFake{SeqAck: packet.SeqAck{Seq: 1, Ack: 2}, BadMD5Sig: true}
	_, err := rw.WriteCraftedPacketWithSeq(
		context.Background(),
		nil,
		nil,
		5,
		[]byte("a"),
		first,
	)
	require.NoError(t, err)
	_, err = rw.WriteCraftedPacketWithSeq(context.Background(), nil, nil, 5, []byte("b"),
		packet.TCPFake{SeqAck: packet.SeqAck{Seq: 2, Ack: 2}})
	require.NoError(t, err)
	assert.Equal(t, fakeLog{sent: 2, first: first, pieces: []fakePiece{
		{SeqAck: packet.SeqAck{Seq: 1, Ack: 2}, length: 1},
		{SeqAck: packet.SeqAck{Seq: 2, Ack: 2}, length: 1},
	}}, *log)

	w.err = errors.New("boom")
	_, err = rw.WriteCraftedPacketWithSeq(
		context.Background(),
		nil,
		nil,
		5,
		[]byte("c"),
		first,
	)
	require.Error(t, err)
	assert.Equal(t, 2, log.sent)
	assert.EqualError(t, log.err, "boom")
}

// TestFakeDesyncer drives spoofdpi's desyncer with the probe's adapters,
// as packetFakes builds it, on a loopback connection whose sequence
// numbers the tracker knows.
func TestFakeDesyncer(t *testing.T) {
	variants := []fakeVariant{
		ttlVariant,
		seqVariant(1),
		seqVariant(maxOffset),
		ackVariant(1),
		ackVariant(maxOffset),
		badMD5Variant,
	}
	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			client, server := loopbackPair(t)
			got := make(chan []byte, 1)
			go func() {
				buf := make([]byte, 4096)
				n, _ := server.Read(buf)
				got <- buf[:n]
			}()

			real := packet.SeqAck{Seq: 1000, Ack: 70000}
			seqs := packet.NewSeqTracker(time.Second)
			seqs.Put(packet.SeqKey(
				client.LocalAddr().(*net.TCPAddr),
				client.RemoteAddr().(*net.TCPAddr),
			), real)
			w := &stubWriter{}
			log := &fakeLog{}
			d := desync.NewTLSDesyncer(
				zerolog.Nop(),
				recordingWriter{
					TCPSeqWriter: fixedTTLWriter{TCPSeqWriter: w, ttl: 7},
					log:          log,
				},
				unlearnedHops{HopReader: &stubHops{}},
				seqs,
			)
			msg, err := buildClientHello("www.example.com")
			require.NoError(t, err)
			_, err = d.Desync(
				context.Background(), client, msg, fakeOpts(v), &config.ConnOptions{},
			)
			require.NoError(t, err)

			require.Len(t, w.sent, 1, "one fake, in one piece")
			sent := w.sent[0]
			assert.Equal(t, uint8(7), sent.ttl)
			assert.Equal(t, []byte(config.FakeClientHello), sent.payload)
			assert.Equal(t, packet.TCPFake{
				SeqAck: fakeSeqAck(real, v), BadMD5Sig: v.badMD5,
			}, sent.fake)
			assert.Equal(t, fakeLog{sent: 1, first: sent.fake, pieces: []fakePiece{
				{SeqAck: sent.fake.SeqAck, length: len(sent.payload)},
			}}, *log)
			assert.Equal(t, msg.Raw()[:10], (<-got)[:10], "the real ClientHello follows")
		})
	}
}

func TestFakeSeqAck_LargestOffset(t *testing.T) {
	real := packet.SeqAck{Seq: 1000, Ack: 70000}
	assert.Equal(t,
		packet.SeqAck{Seq: 1000 + 1<<31, Ack: 70000},
		fakeSeqAck(real, seqVariant(maxOffset)),
		"-2^31 wraps to +2^31 mod 2^32")
	assert.Equal(t,
		packet.SeqAck{Seq: 1000, Ack: 70000 + 1<<31},
		fakeSeqAck(real, ackVariant(maxOffset)))
}
