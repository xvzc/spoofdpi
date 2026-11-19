package desync

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/packet"
	"github.com/xvzc/spoofdpi/internal/proto"
)

type writtenPacket struct {
	payload []byte
	seq     packet.SeqAck
}

type recordingWriter struct {
	packets []writtenPacket
}

func (w *recordingWriter) WriteCraftedPacket(
	_ context.Context, _, _ net.Addr, _ uint8, payload []byte,
) (int, error) {
	panic("fake TCP packets must carry explicit sequence numbers")
}

func (w *recordingWriter) WriteCraftedPacketWithSeq(
	_ context.Context, _, _ net.Addr, _ uint8, payload []byte, seq packet.SeqAck,
) (int, error) {
	w.packets = append(w.packets, writtenPacket{payload: payload, seq: seq})
	return len(payload), nil
}

type stubSniffer struct{ hopLearned bool }

func (stubSniffer) StartCapturing()                   {}
func (stubSniffer) Register([]net.IP)                 {}
func (s stubSniffer) HopLearned(netutil.IPKey) bool   { return s.hopLearned }
func (stubSniffer) GetOptimalTTL(netutil.IPKey) uint8 { return 8 }

// stubConn is a net.Conn with TCP addresses that accepts every write.
type stubConn struct {
	net.Conn
	local, remote *net.TCPAddr
}

func (c *stubConn) LocalAddr() net.Addr         { return c.local }
func (c *stubConn) RemoteAddr() net.Addr        { return c.remote }
func (c *stubConn) Write(b []byte) (int, error) { return len(b), nil }

func newStubConn(remoteIP string) *stubConn {
	return &stubConn{
		local:  &net.TCPAddr{IP: net.ParseIP("192.168.1.11"), Port: 50000},
		remote: &net.TCPAddr{IP: net.ParseIP(remoteIP), Port: 443},
	}
}

func tlsOpts(fakeCount, chunkSize uint8) *config.HTTPSOptions {
	return &config.HTTPSOptions{
		FakeCount:     fakeCount,
		FakePacket:    proto.NewFakeTLSMessage([]byte(config.FakeClientHello)),
		SplitMode:     config.HTTPSSplitModeChunk,
		ChunkSize:     chunkSize,
		SynAckTimeout: 100 * time.Millisecond,
	}
}

func fakeMsg() *proto.TLSMessage {
	return proto.NewFakeTLSMessage([]byte(config.FakeClientHello))
}

func TestSendFakePackets_SegmentsAndCopies(t *testing.T) {
	w := &recordingWriter{}
	d := NewTLSDesyncer(zerolog.Nop(), w, stubSniffer{}, nil)
	fake := packet.SeqAck{Seq: 1000, Ack: 5000}

	_, err := d.sendFakePackets(
		context.Background(),
		zerolog.Nop(),
		newStubConn("203.0.113.1"),
		8,
		tlsOpts(2, 100),
		fake,
	)
	require.NoError(t, err)

	perCopy := (len(config.FakeClientHello) + 99) / 100
	require.Len(t, w.packets, 2*perCopy)
	for c := range 2 {
		want := uint32(1000)
		for i := range perCopy {
			p := w.packets[c*perCopy+i]
			assert.Equal(t, want, p.seq.Seq, "copy %d segment %d", c, i)
			assert.Equal(t, uint32(5000), p.seq.Ack)
			want += uint32(len(p.payload))
		}
	}
}

func TestApplySeqMode(t *testing.T) {
	tcs := []struct {
		name string
		mode config.SeqMode
		real uint32
		want uint32
	}{
		{"offset 0 keeps the real number", config.SeqMode{}, 5000, 5000},
		{"negative offset", config.SeqMode{Offset: -10000}, 20000, 10000},
		{"negative offset wraps", config.SeqMode{Offset: -10000}, 5000, 1<<32 - 5000},
		{"positive offset", config.SeqMode{Offset: 66000}, 5000, 71000},
		{"positive offset wraps", config.SeqMode{Offset: 1 << 31}, 1 << 31, 0},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, applySeqMode(tc.mode, tc.real))
		})
	}

	t.Run("seq and ack are independent", func(t *testing.T) {
		opts := &config.HTTPSOptions{
			FakeSeq: config.SeqMode{Offset: -10000},
			FakeAck: config.SeqMode{Offset: 66000},
		}
		got := fakeSeqAck(packet.SeqAck{Seq: 20000, Ack: 30000}, opts)
		assert.Equal(t, packet.SeqAck{Seq: 10000, Ack: 96000}, got)
	})
}

func TestSendSegments_AdvancesSeq(t *testing.T) {
	d := NewTLSDesyncer(zerolog.Nop(), nil, nil, nil)
	seq := &packet.SeqAck{Seq: 1000, Ack: 5000}

	n, err := d.sendSegments(
		newStubConn("203.0.113.1"),
		zerolog.Nop(),
		[]Segment{{Packet: []byte("abc")}, {Packet: []byte("defgh")}},
		seq,
	)
	require.NoError(t, err)
	assert.Equal(t, 8, n)
	assert.Equal(t, packet.SeqAck{Seq: 1008, Ack: 5000}, *seq)
}

func TestDesync_UsesLearnedSeqAckWithOffsets(t *testing.T) {
	w := &recordingWriter{}
	seqs := packet.NewSeqTracker(time.Minute)
	d := NewTLSDesyncer(zerolog.Nop(), w, stubSniffer{}, seqs)
	conn := newStubConn("203.0.113.1")
	seqs.Put(
		packet.SeqKey(conn.local, conn.remote),
		packet.SeqAck{Seq: 20000, Ack: 30000},
	)

	opts := tlsOpts(1, 100)
	opts.FakeSeq = config.SeqMode{Offset: -10000}
	opts.FakeAck = config.SeqMode{Offset: 66000}

	_, err := d.Desync(context.Background(), conn, fakeMsg(), opts)
	require.NoError(t, err)

	require.NotEmpty(t, w.packets)
	assert.Equal(t, packet.SeqAck{Seq: 10000, Ack: 96000}, w.packets[0].seq)
}

func TestDesync_UnlearnedFakeSegmentsLineUp(t *testing.T) {
	w := &recordingWriter{}
	d := NewTLSDesyncer(
		zerolog.Nop(),
		w,
		stubSniffer{},
		packet.NewSeqTracker(time.Minute),
	)
	opts := tlsOpts(1, 100)
	opts.SynAckTimeout = 0

	_, err := d.Desync(context.Background(), newStubConn("203.0.113.1"), fakeMsg(), opts)
	require.NoError(t, err)

	require.Greater(t, len(w.packets), 1)
	for i := 1; i < len(w.packets); i++ {
		prev, cur := w.packets[i-1], w.packets[i]
		assert.Equal(t, prev.seq.Seq+uint32(len(prev.payload)), cur.seq.Seq,
			"segments of one fake are contiguous even with random numbers")
		assert.Equal(t, prev.seq.Ack, cur.seq.Ack)
	}
}

// TestDesync_WaitRules checks when Desync waits for the SYN/ACK. Nothing is
// ever learned here, so a wait always runs until SynAckTimeout.
func TestDesync_WaitRules(t *testing.T) {
	const timeout = 200 * time.Millisecond

	tcs := []struct {
		name       string
		remote     string
		fakeCount  uint8
		randBoth   bool
		hopLearned bool
		timeout    time.Duration
		wantWait   bool
	}{
		{"offset mode waits", "203.0.113.1", 1, false, true, timeout, true},
		{
			"rand mode waits for an unlearned hop",
			"203.0.113.1",
			1,
			true,
			false,
			timeout,
			true,
		},
		{
			"rand mode skips the wait once the hop is learned",
			"203.0.113.1",
			1,
			true,
			true,
			timeout,
			false,
		},
		{"timeout 0 does not wait", "203.0.113.1", 1, false, false, 0, false},
		{"private server does not wait", "192.168.1.1", 1, false, false, timeout, false},
		{"ipv6 server does not wait", "2001:db8::1", 1, false, false, timeout, false},
		{"no fakes, no wait", "203.0.113.1", 0, false, false, timeout, false},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			d := NewTLSDesyncer(
				zerolog.Nop(),
				&recordingWriter{},
				stubSniffer{hopLearned: tc.hopLearned},
				packet.NewSeqTracker(time.Minute),
			)
			opts := tlsOpts(tc.fakeCount, 100)
			opts.SynAckTimeout = tc.timeout
			if tc.randBoth {
				opts.FakeSeq = config.SeqMode{Random: true}
				opts.FakeAck = config.SeqMode{Random: true}
			}

			start := time.Now()
			_, err := d.Desync(context.Background(), newStubConn(tc.remote), fakeMsg(), opts)
			require.NoError(t, err)
			elapsed := time.Since(start)

			if tc.wantWait {
				assert.GreaterOrEqual(t, elapsed, timeout-20*time.Millisecond)
			} else {
				assert.Less(t, elapsed, timeout/2)
			}
		})
	}
}
