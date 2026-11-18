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
	seq     *packet.TCPSeq // nil when sent with random sequence numbers
}

type recordingWriter struct {
	packets []writtenPacket
}

func (w *recordingWriter) WriteCraftedPacket(
	_ context.Context, _, _ net.Addr, _ uint8, payload []byte,
) (int, error) {
	w.packets = append(w.packets, writtenPacket{payload: payload})
	return len(payload), nil
}

func (w *recordingWriter) WriteCraftedPacketWithSeq(
	_ context.Context, _, _ net.Addr, _ uint8, payload []byte, seq packet.TCPSeq,
) (int, error) {
	w.packets = append(w.packets, writtenPacket{payload: payload, seq: &seq})
	return len(payload), nil
}

type stubSniffer struct{}

func (stubSniffer) StartCapturing()                   {}
func (stubSniffer) Register([]net.IP)                 {}
func (stubSniffer) GetOptimalTTL(netutil.IPKey) uint8 { return 8 }

// stubConn is a net.Conn with TCP addresses that accepts every write.
type stubConn struct {
	net.Conn
	local, remote *net.TCPAddr
	written       [][]byte
}

func (c *stubConn) LocalAddr() net.Addr  { return c.local }
func (c *stubConn) RemoteAddr() net.Addr { return c.remote }
func (c *stubConn) Write(b []byte) (int, error) {
	c.written = append(c.written, append([]byte(nil), b...))
	return len(b), nil
}

func newStubConn() *stubConn {
	return &stubConn{
		local:  &net.TCPAddr{IP: net.ParseIP("192.168.1.11"), Port: 50000},
		remote: &net.TCPAddr{IP: net.ParseIP("203.0.113.1"), Port: 443},
	}
}

func chunkOpts(fakeCount uint8, chunkSize uint8) *config.HTTPSOptions {
	return &config.HTTPSOptions{
		FakeCount:  fakeCount,
		FakePacket: proto.NewFakeTLSMessage([]byte(config.FakeClientHello)),
		SplitMode:  config.HTTPSSplitModeChunk,
		ChunkSize:  chunkSize,
	}
}

func TestSendFakePackets_UsesSeqPerSegment(t *testing.T) {
	w := &recordingWriter{}
	d := NewTLSDesyncer(zerolog.Nop(), w, stubSniffer{}, nil)
	opts := chunkOpts(2, 100)
	seq := &packet.TCPSeq{Seq: 1000, Ack: 5000}

	_, err := d.sendFakePackets(
		context.Background(),
		zerolog.Nop(),
		newStubConn(),
		8,
		opts,
		seq,
	)
	require.NoError(t, err)

	fakeLen := len(config.FakeClientHello)
	perCopy := (fakeLen + 99) / 100
	require.Len(t, w.packets, 2*perCopy)

	for c := range 2 {
		want := uint32(1000)
		for i := range perCopy {
			p := w.packets[c*perCopy+i]
			require.NotNil(t, p.seq)
			assert.Equal(t, want, p.seq.Seq, "copy %d segment %d", c, i)
			assert.Equal(t, uint32(5000), p.seq.Ack)
			want += uint32(len(p.payload))
		}
	}

	assert.Equal(t, packet.TCPSeq{Seq: 1000, Ack: 5000}, *seq, "fakes do not advance seq")
}

func TestSendFakePackets_RandomWithoutSeq(t *testing.T) {
	w := &recordingWriter{}
	d := NewTLSDesyncer(zerolog.Nop(), w, stubSniffer{}, nil)

	_, err := d.sendFakePackets(
		context.Background(), zerolog.Nop(), newStubConn(), 8, chunkOpts(1, 100), nil,
	)
	require.NoError(t, err)
	require.NotEmpty(t, w.packets)
	for _, p := range w.packets {
		assert.Nil(t, p.seq)
	}
}

func TestSendSegments_AdvancesSeq(t *testing.T) {
	d := NewTLSDesyncer(zerolog.Nop(), nil, nil, nil)
	conn := newStubConn()
	seq := &packet.TCPSeq{Seq: 1000, Ack: 5000}

	segments := []Segment{
		{Packet: []byte("abc")},
		{Packet: []byte("defgh")},
	}

	n, err := d.sendSegments(conn, zerolog.Nop(), segments, seq)
	require.NoError(t, err)
	assert.Equal(t, 8, n)
	assert.Equal(t, packet.TCPSeq{Seq: 1008, Ack: 5000}, *seq)
}

func TestDesync_UsesLearnedSeq(t *testing.T) {
	w := &recordingWriter{}
	seqs := packet.NewSeqTracker(time.Minute)
	d := NewTLSDesyncer(zerolog.Nop(), w, stubSniffer{}, seqs)
	conn := newStubConn()

	seqs.Put(packet.SeqKey(conn.local, conn.remote), packet.TCPSeq{Seq: 1000, Ack: 5000})

	msg := proto.NewFakeTLSMessage([]byte(config.FakeClientHello))
	_, err := d.Desync(context.Background(), conn, msg, chunkOpts(1, 100))
	require.NoError(t, err)

	require.NotEmpty(t, w.packets)
	require.NotNil(t, w.packets[0].seq)
	assert.Equal(t, uint32(1000), w.packets[0].seq.Seq)
	assert.Equal(t, uint32(5000), w.packets[0].seq.Ack)
}

func TestDesync_FallsBackToRandomSeq(t *testing.T) {
	w := &recordingWriter{}
	seqs := packet.NewSeqTracker(time.Minute)
	d := NewTLSDesyncer(zerolog.Nop(), w, stubSniffer{}, seqs)

	msg := proto.NewFakeTLSMessage([]byte(config.FakeClientHello))
	_, err := d.Desync(context.Background(), newStubConn(), msg, chunkOpts(1, 100))
	require.NoError(t, err)

	require.NotEmpty(t, w.packets)
	for _, p := range w.packets {
		assert.Nil(t, p.seq)
	}
}
