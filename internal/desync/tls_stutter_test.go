package desync

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/proto"
)

// event is a packet put on the wire: a crafted fake, or a real write.
type event struct {
	fake    bool
	seq     SeqAck // fakes only
	md5     bool   // fakes only
	payload []byte
}

type eventLog struct{ events []event }

// eventWriter records crafted fakes. If failAt > 0, the failAt-th fake
// (1-based) and every later one fail.
type eventWriter struct {
	log    *eventLog
	failAt int
	sent   *int
}

func (w eventWriter) WriteCraftedPacket(
	context.Context, net.Addr, net.Addr, uint8, []byte,
) (int, error) {
	panic("fake TCP packets must carry explicit sequence numbers")
}

func (w eventWriter) WriteCraftedPacketWithSeq(
	_ context.Context, _, _ net.Addr, _ uint8, payload []byte, fake TCPFake,
) (int, error) {
	if w.failAt > 0 {
		*w.sent++
		if *w.sent >= w.failAt {
			return 0, errors.New("injected writer failure")
		}
	}
	w.log.events = append(w.log.events, event{
		fake: true, seq: fake.SeqAck, md5: fake.BadMD5Sig, payload: payload,
	})
	return len(payload), nil
}

type eventConn struct {
	*stubConn
	log *eventLog
}

func (c eventConn) Write(b []byte) (int, error) {
	c.log.events = append(c.log.events, event{payload: append([]byte(nil), b...)})
	return len(b), nil
}

// stutterRun runs Desync over the built-in Client Hello split into
// 100-byte chunks, with the real numbers learned as {1000, 5000} and a
// 300-byte fake packet of 0xAB.
func stutterRun(t *testing.T, mutate func(*config.HTTPSOptions)) ([]event, []byte) {
	t.Helper()
	return stutterRunWith(t, SeqAck{Seq: 1000, Ack: 5000}, 0, mutate)
}

// stutterRunWith is stutterRun with the learned numbers and the writer's
// failAt given.
func stutterRunWith(
	t *testing.T,
	real SeqAck,
	failAt int,
	mutate func(*config.HTTPSOptions),
) ([]event, []byte) {
	t.Helper()

	log := &eventLog{}
	var sent int
	seqs := NewSeqTracker(time.Minute)
	d := NewTLSDesyncer(
		zerolog.Nop(),
		eventWriter{log: log, failAt: failAt, sent: &sent},
		stubHops{hopLearned: true, hops: 10},
		seqs,
		nil,
	)
	sc := newStubConn("203.0.113.1")
	seqs.Put(SeqKey(sc.local, sc.remote), real)

	opts := tlsOpts(0, 100)
	opts.FakePacket = proto.NewFakeTLSMessage(bytes.Repeat([]byte{0xAB}, 300))
	mutate(opts)

	msg := fakeMsg()
	_, err := d.Desync(
		context.Background(),
		eventConn{sc, log},
		msg,
		opts,
		baseConnOpts(),
	)
	require.NoError(t, err)

	return log.events, msg.Raw()
}

func wantFakeBytes(offset, length int) []byte {
	out := make([]byte, length)
	for i := range out {
		if offset+i < 300 {
			out[i] = 0xAB
		}
	}
	return out
}

func TestStutter_FakesPrecedeEachSegment(t *testing.T) {
	events, raw := stutterRun(t, func(o *config.HTTPSOptions) { o.FakeStutter = 2 })

	segments := (len(raw) + 99) / 100
	require.Len(t, events, segments*3, "2 fakes + 1 real per segment")

	offset := 0
	for k := range segments {
		length := min(100, len(raw)-offset)
		for i := range 2 {
			e := events[3*k+i]
			require.True(t, e.fake, "segment %d event %d is a fake", k, i)
			assert.Equal(t, SeqAck{Seq: uint32(1000 + offset), Ack: 5000}, e.seq)
			assert.Equal(t, wantFakeBytes(offset, length), e.payload, "segment %d", k)
		}
		r := events[3*k+2]
		require.False(t, r.fake)
		assert.Equal(t, raw[offset:offset+length], r.payload)
		offset += length
	}
}

func TestStutter_AfterPreflight(t *testing.T) {
	events, raw := stutterRun(t, func(o *config.HTTPSOptions) {
		o.FakePreflight = 1
		o.FakeStutter = 1
	})

	// Preflight: the 300-byte fake split into 100-byte chunks, from 1000.
	for i := range 3 {
		e := events[i]
		require.True(t, e.fake)
		assert.Equal(t, uint32(1000+100*i), e.seq.Seq)
		assert.Len(t, e.payload, 100)
	}
	// Then one stutter fake before each real segment.
	rest := events[3:]
	segments := (len(raw) + 99) / 100
	require.Len(t, rest, segments*2)
	for k := range segments {
		assert.True(t, rest[2*k].fake)
		assert.Equal(t, uint32(1000+100*k), rest[2*k].seq.Seq)
		assert.False(t, rest[2*k+1].fake)
	}
}

func TestStutter_SeqAckOffsets(t *testing.T) {
	t.Run("offsets apply to every stutter fake", func(t *testing.T) {
		events, _ := stutterRun(t, func(o *config.HTTPSOptions) {
			o.FakeStutter = 1
			o.FakeSeqOffset = -10
			o.FakeAckOffset = -1073741824
		})
		for k, want := range []uint32{990, 1090, 1190} {
			assert.Equal(t, want, events[2*k].seq.Seq, "stutter fake %d", k)
			assert.Equal(t, uint32(5000+(1<<32)-1073741824), events[2*k].seq.Ack)
		}
	})

	t.Run("preflight and stutter share the offsets", func(t *testing.T) {
		events, _ := stutterRun(t, func(o *config.HTTPSOptions) {
			o.FakePreflight = 1
			o.FakeStutter = 1
			o.FakeSeqOffset = -10000
		})
		assert.Equal(t, uint32(1000+(1<<32)-10000), events[0].seq.Seq, "preflight")
		assert.Equal(t, uint32(1000+(1<<32)-10000), events[3].seq.Seq, "first stutter fake")
	})
}

func TestStutter_Disabled(t *testing.T) {
	t.Run("preflight only sends no per-segment fakes", func(t *testing.T) {
		events, raw := stutterRun(t, func(o *config.HTTPSOptions) { o.FakePreflight = 1 })
		segments := (len(raw) + 99) / 100
		require.Len(t, events, 3+segments)
		for _, e := range events[3:] {
			assert.False(t, e.fake)
		}
	})

	t.Run("no fakes on the local link", func(t *testing.T) {
		log := &eventLog{}
		d := NewTLSDesyncer(
			zerolog.Nop(),
			eventWriter{log: log},
			stubHops{hopLearned: true, hops: 0},
			nil,
			nil,
		)
		opts := tlsOpts(0, 100)
		opts.FakeStutter = 2
		opts.SynAckTimeout = 0
		_, err := d.Desync(
			context.Background(),
			eventConn{newStubConn("192.168.1.20"), log},
			fakeMsg(),
			opts,
			baseConnOpts(),
		)
		require.NoError(t, err)
		for _, e := range log.events {
			assert.False(t, e.fake)
		}
	})
}

func TestFakeRange(t *testing.T) {
	fake := []byte{1, 2, 3, 4}
	assert.Equal(t, []byte{2, 3}, fakeRange(fake, 1, 2))
	assert.Equal(t, []byte{3, 4, 0, 0}, fakeRange(fake, 2, 4))
	assert.Equal(t, []byte{0, 0}, fakeRange(fake, 10, 2))
}

func TestStutter_WithDisorder(t *testing.T) {
	events, raw := stutterRun(t, func(o *config.HTTPSOptions) {
		o.FakeStutter = 1
		o.Disorder = true
	})

	// Every real segment, lazy or not, is preceded by its fake, and the
	// real bytes still go out in order.
	segments := (len(raw) + 99) / 100
	require.Len(t, events, segments*2)
	var got []byte
	for k := range segments {
		require.True(t, events[2*k].fake, "segment %d", k)
		assert.Equal(t, uint32(1000+100*k), events[2*k].seq.Seq)
		require.False(t, events[2*k+1].fake, "segment %d", k)
		got = append(got, events[2*k+1].payload...)
	}
	assert.Equal(t, raw, got)
}

func TestStutter_WriterError(t *testing.T) {
	// The 3rd fake fails: stutter stops, but every real segment is sent.
	events, raw := stutterRunWith(t, SeqAck{Seq: 1000, Ack: 5000}, 3,
		func(o *config.HTTPSOptions) { o.FakeStutter = 1 })

	var fakes int
	var got []byte
	for _, e := range events {
		if e.fake {
			fakes++
		} else {
			got = append(got, e.payload...)
		}
	}
	assert.Equal(t, 2, fakes)
	assert.Equal(t, raw, got)
}

func TestStutter_SeqWrapAround(t *testing.T) {
	start := uint32(0xFFFFFFC0)
	events, raw := stutterRunWith(t, SeqAck{Seq: start, Ack: 5000}, 0,
		func(o *config.HTTPSOptions) {
			o.FakePreflight = 1
			o.FakeStutter = 1
			o.FakeSeqOffset = -10
		})

	// Preflight: the 300-byte fake in three pieces from start-10.
	for k := range 3 {
		assert.Equal(t, start-10+uint32(100*k), events[k].seq.Seq, "preflight piece %d", k)
	}
	assert.Equal(t, uint32(0x24-10+100), events[2].seq.Seq, "wraps past 2^32")

	// Stutter: each segment's sequence number minus 10.
	rest := events[3:]
	segments := (len(raw) + 99) / 100
	for k := range segments {
		assert.Equal(t, start+uint32(100*k)-10, rest[2*k].seq.Seq, "segment %d", k)
	}
	assert.Equal(t, uint32(0x24-10), rest[2].seq.Seq, "wraps past 2^32")
}

func TestFakeSender_SplitsByMSS(t *testing.T) {
	newSender := func(log *eventLog, preflight, stutter uint8) *fakeSender {
		opts := tlsOpts(preflight, 100)
		opts.SplitMode = config.HTTPSSplitModeNone
		opts.FakeStutter = stutter
		opts.FakePacket = proto.NewFakeTLSMessage(bytes.Repeat([]byte{0xAB}, 120))
		f := newFakeSender(eventWriter{log: log}, newStubConn("203.0.113.1"), 8, opts,
			SeqAck{Seq: 1000, Ack: 5000})
		f.mss = 50
		return f
	}
	pieces := func(events []event) (seqs []uint32, lens []int) {
		for _, e := range events {
			seqs = append(seqs, e.seq.Seq)
			lens = append(lens, len(e.payload))
		}
		return seqs, lens
	}

	t.Run("stutter", func(t *testing.T) {
		log := &eventLog{}
		n, err := newSender(log, 0, 1).stutter(
			context.Background(), SeqAck{Seq: 2000, Ack: 5000}, 0, 120)
		require.NoError(t, err)
		assert.Equal(t, 120, n)
		seqs, lens := pieces(log.events)
		assert.Equal(t, []uint32{2000, 2050, 2100}, seqs)
		assert.Equal(t, []int{50, 50, 20}, lens)
	})

	t.Run("preflight", func(t *testing.T) {
		log := &eventLog{}
		n, err := newSender(log, 1, 0).preflight(context.Background(), zerolog.Nop())
		require.NoError(t, err)
		assert.Equal(t, 120, n)
		seqs, lens := pieces(log.events)
		assert.Equal(t, []uint32{1000, 1050, 1100}, seqs)
		assert.Equal(t, []int{50, 50, 20}, lens)
	})

	t.Run("short payloads are one packet", func(t *testing.T) {
		log := &eventLog{}
		_, err := newSender(log, 0, 1).stutter(
			context.Background(), SeqAck{Seq: 2000, Ack: 5000}, 0, 50)
		require.NoError(t, err)
		assert.Len(t, log.events, 1)
	})
}

func TestConnMSS(t *testing.T) {
	t.Run("fallback when it cannot be read", func(t *testing.T) {
		assert.Equal(t, fallbackMSS, connMSS(newStubConn("203.0.113.1")))
	})

	t.Run("real tcp connection", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer func() { _ = ln.Close() }()
		go func() {
			if c, err := ln.Accept(); err == nil {
				defer func() { _ = c.Close() }()
				time.Sleep(100 * time.Millisecond)
			}
		}()

		conn, err := net.Dial("tcp", ln.Addr().String())
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()

		mss := connMSS(conn)
		assert.Positive(t, mss)
		assert.NotEqual(t, fallbackMSS, mss, "read from the socket")
	})
}

func TestFakeSender_BadMD5Sig(t *testing.T) {
	t.Run("every fake carries the option", func(t *testing.T) {
		events, _ := stutterRun(t, func(o *config.HTTPSOptions) {
			o.FakePreflight = 1
			o.FakeStutter = 1
			o.FakeBadMD5Sig = true
		})
		var fakes int
		for _, e := range events {
			if e.fake {
				fakes++
				assert.True(t, e.md5)
			}
		}
		assert.Positive(t, fakes)
	})

	t.Run("off by default", func(t *testing.T) {
		events, _ := stutterRun(t, func(o *config.HTTPSOptions) { o.FakeStutter = 1 })
		for _, e := range events {
			assert.False(t, e.md5)
		}
	})

	t.Run("pieces leave room for the option", func(t *testing.T) {
		opts := tlsOpts(0, 100)
		assert.Equal(t, fallbackMSS, fakeMSS(newStubConn("203.0.113.1"), opts))
		opts.FakeBadMD5Sig = true
		assert.Equal(t, fallbackMSS-MD5SigOptionLen,
			fakeMSS(newStubConn("203.0.113.1"), opts))
	})
}
