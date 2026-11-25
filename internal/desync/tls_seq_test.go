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
	"github.com/xvzc/spoofdpi/internal/proto"
)

type writtenPacket struct {
	ttl     uint8
	payload []byte
	seq     SeqAck
	md5     bool
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
	_ context.Context, _, _ net.Addr, ttl uint8, payload []byte, fake TCPFake,
) (int, error) {
	w.packets = append(
		w.packets,
		writtenPacket{ttl: ttl, payload: payload, seq: fake.SeqAck, md5: fake.BadMD5Sig},
	)
	return len(payload), nil
}

// stubHops is a hop reader that has every server registered, with hops
// learned if hopLearned is set.
type stubHops struct {
	hopLearned bool
	hops       uint8
}

func (stubHops) Register(Proto, []net.IP)      {}
func (stubHops) MarkWarned(Proto, net.IP) bool { return true }
func (s stubHops) Lookup(Proto, net.IP) HopEstimate {
	if !s.hopLearned {
		return HopEstimate{Source: HopSourceDefault}
	}
	return HopEstimate{Hops: s.hops, Source: HopSourceLearned}
}

// baseConnOpts are the default hop-count options.
func baseConnOpts() *config.ConnOptions {
	return &config.ConnOptions{HopCountDefault: 8, HopCountMax: 255, HopCountOffset: -1}
}

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
		FakePreflight: fakeCount,
		FakePacket:    proto.NewFakeTLSMessage([]byte(config.FakeClientHello)),
		SplitMode:     config.HTTPSSplitModeChunk,
		ChunkSize:     chunkSize,
		SynAckTimeout: 100 * time.Millisecond,
	}
}

func fakeMsg() *proto.TLSMessage {
	return proto.NewFakeTLSMessage([]byte(config.FakeClientHello))
}

func TestFakeSenderPreflight_SegmentsAndCopies(t *testing.T) {
	w := &recordingWriter{}
	f := newFakeSender(
		w, newStubConn("203.0.113.1"), 8, tlsOpts(2, 100),
		SeqAck{Seq: 1000, Ack: 5000},
	)

	_, err := f.preflight(context.Background(), zerolog.Nop())
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

func TestFakeSeqAck(t *testing.T) {
	tcs := []struct {
		name     string
		seq, ack int64
		real     SeqAck
		want     SeqAck
	}{
		{
			"offset 0 keeps the real numbers",
			0,
			0,
			SeqAck{Seq: 5000, Ack: 7000},
			SeqAck{Seq: 5000, Ack: 7000},
		},
		{
			"negative offsets",
			-10000,
			-1000,
			SeqAck{Seq: 20000, Ack: 30000},
			SeqAck{Seq: 10000, Ack: 29000},
		},
		{
			"negative offset wraps",
			-10000,
			0,
			SeqAck{Seq: 5000, Ack: 1},
			SeqAck{Seq: 1<<32 - 5000, Ack: 1},
		},
		{
			"positive offset",
			66000,
			66000,
			SeqAck{Seq: 5000, Ack: 5000},
			SeqAck{Seq: 71000, Ack: 71000},
		},
		{
			"positive offset wraps",
			1 << 31,
			0,
			SeqAck{Seq: 1 << 31, Ack: 1},
			SeqAck{Seq: 0, Ack: 1},
		},
		{
			"largest offsets",
			1<<32 - 1,
			-(1<<32 - 1),
			SeqAck{Seq: 5, Ack: 5},
			SeqAck{Seq: 4, Ack: 6},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			opts := &config.HTTPSOptions{FakeSeqOffset: tc.seq, FakeAckOffset: tc.ack}
			assert.Equal(t, tc.want, fakeSeqAck(tc.real, opts))
		})
	}
}

func TestSendSegments_AdvancesSeq(t *testing.T) {
	d := NewTLSDesyncer(zerolog.Nop(), nil, nil, nil, nil)
	seq := &SeqAck{Seq: 1000, Ack: 5000}

	n, err := d.sendSegments(
		context.Background(),
		newStubConn("203.0.113.1"),
		zerolog.Nop(),
		[]Segment{{Packet: []byte("abc")}, {Packet: []byte("defgh")}},
		seq,
		nil,
	)
	require.NoError(t, err)
	assert.Equal(t, 8, n)
	assert.Equal(t, SeqAck{Seq: 1008, Ack: 5000}, *seq)
}

func TestDesync_UsesLearnedSeqAckWithOffsets(t *testing.T) {
	w := &recordingWriter{}
	seqs := NewSeqTracker(time.Minute)
	d := NewTLSDesyncer(zerolog.Nop(), w, stubHops{}, seqs, nil)
	conn := newStubConn("203.0.113.1")
	seqs.Put(
		SeqKey(conn.local, conn.remote),
		SeqAck{Seq: 20000, Ack: 30000},
	)

	opts := tlsOpts(1, 100)
	opts.FakeSeqOffset = -10000
	opts.FakeAckOffset = 66000

	_, err := d.Desync(context.Background(), conn, fakeMsg(), opts, baseConnOpts())
	require.NoError(t, err)

	require.NotEmpty(t, w.packets)
	assert.Equal(t, SeqAck{Seq: 10000, Ack: 96000}, w.packets[0].seq)
}

func TestDesync_UnlearnedFakeSegmentsLineUp(t *testing.T) {
	w := &recordingWriter{}
	d := NewTLSDesyncer(
		zerolog.Nop(),
		w,
		stubHops{},
		NewSeqTracker(time.Minute),
		nil,
	)
	opts := tlsOpts(1, 100)
	opts.SynAckTimeout = 0

	_, err := d.Desync(
		context.Background(), newStubConn("203.0.113.1"), fakeMsg(), opts, baseConnOpts(),
	)
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
		hopLearned bool
		timeout    time.Duration
		wantWait   bool
	}{
		{"waits", "203.0.113.1", 1, false, timeout, true},
		{"waits even once the hop is learned", "203.0.113.1", 1, true, timeout, true},
		{"timeout 0 does not wait", "203.0.113.1", 1, false, 0, false},
		{"private server waits", "192.168.1.1", 1, false, timeout, true},
		{"ipv6 server does not wait", "2001:db8::1", 1, false, timeout, false},
		{"no fakes, no wait", "203.0.113.1", 0, false, timeout, false},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			d := NewTLSDesyncer(
				zerolog.Nop(),
				&recordingWriter{},
				stubHops{hopLearned: tc.hopLearned},
				NewSeqTracker(time.Minute),
				nil,
			)
			opts := tlsOpts(tc.fakeCount, 100)
			opts.SynAckTimeout = tc.timeout

			start := time.Now()
			_, err := d.Desync(
				context.Background(), newStubConn(tc.remote), fakeMsg(), opts, baseConnOpts(),
			)
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

func TestDesync_SkipsFakesOnLocalLink(t *testing.T) {
	tcs := []struct {
		name      string
		hops      stubHops
		wantFakes bool
	}{
		{"server on the local link", stubHops{hopLearned: true, hops: 0}, false},
		{"server one hop away", stubHops{hopLearned: true, hops: 1}, true},
		{"hop count not learned", stubHops{}, true},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			w := &recordingWriter{}
			d := NewTLSDesyncer(zerolog.Nop(), w, tc.hops, nil, nil)
			opts := tlsOpts(1, 100)
			opts.SynAckTimeout = 0

			n, err := d.Desync(
				context.Background(),
				newStubConn("192.168.1.20"),
				fakeMsg(),
				opts,
				baseConnOpts(),
			)
			require.NoError(t, err)
			assert.Equal(
				t,
				len(config.FakeClientHello),
				n,
				"the real Client Hello is still sent",
			)
			assert.Equal(t, tc.wantFakes, len(w.packets) > 0)
		})
	}
}

func TestOnLocalLink(t *testing.T) {
	tcs := []struct {
		est  HopEstimate
		want bool
	}{
		{HopEstimate{Hops: 0, Source: HopSourceLearned}, true},
		{HopEstimate{Hops: 0, Source: HopSourceLearnedOther}, true},
		{HopEstimate{Hops: 1, Source: HopSourceLearned}, false},
		{HopEstimate{Hops: 0, Source: HopSourceDefault}, false},
	}

	for _, tc := range tcs {
		t.Run(tc.est.Source.String(), func(t *testing.T) {
			assert.Equal(t, tc.want, onLocalLink(tc.est))
		})
	}
}

// udpWriter records crafted UDP packets.
type udpWriter struct {
	n        int
	src, dst net.Addr
	ttl      uint8
}

func (w *udpWriter) WriteCraftedPacket(
	_ context.Context, src, dst net.Addr, ttl uint8, payload []byte,
) (int, error) {
	w.n++
	w.src, w.dst = src, dst
	w.ttl = ttl
	return len(payload), nil
}

type udpConn struct {
	net.Conn
	local, remote *net.UDPAddr
}

func (c udpConn) LocalAddr() net.Addr  { return c.local }
func (c udpConn) RemoteAddr() net.Addr { return c.remote }

func TestUDPDesync_SkipsFakesOnLocalLink(t *testing.T) {
	conn := udpConn{
		local:  &net.UDPAddr{IP: net.ParseIP("192.168.1.11"), Port: 50000},
		remote: &net.UDPAddr{IP: net.ParseIP("192.168.1.20"), Port: 443},
	}
	opts := &config.UDPOptions{FakePreflight: 2, FakePacket: make([]byte, 8)}

	for _, tc := range []struct {
		name      string
		hops      stubHops
		wantFakes int
	}{
		{"server on the local link", stubHops{hopLearned: true, hops: 0}, 0},
		{"server one hop away", stubHops{hopLearned: true, hops: 1}, 2},
		{"hop count not learned", stubHops{}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := &udpWriter{}
			d := NewUDPDesyncer(zerolog.Nop(), w, tc.hops, nil)
			_, err := d.Desync(context.Background(), conn, opts, baseConnOpts())
			require.NoError(t, err)
			assert.Equal(t, tc.wantFakes, w.n)
		})
	}
}

func TestUDPDesync_UsesTheFlowAddresses(t *testing.T) {
	conn := udpConn{
		local:  &net.UDPAddr{IP: net.ParseIP("192.168.1.11"), Port: 50000},
		remote: &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 443},
	}
	w := &udpWriter{}
	d := NewUDPDesyncer(zerolog.Nop(), w, stubHops{}, nil)

	_, err := d.Desync(
		context.Background(),
		conn,
		&config.UDPOptions{FakePreflight: 1, FakePacket: make([]byte, 8)},
		baseConnOpts(),
	)
	require.NoError(t, err)
	assert.Equal(t, conn.local, w.src, "fakes come from the real flow's local address")
	assert.Equal(t, conn.remote, w.dst)
}
