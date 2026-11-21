package probe

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// segment describes a TCP segment for segmentFrame.
type segment struct {
	src, dst netip.AddrPort
	ttl      uint8
	seq, ack uint32
	payload  int
	sack     [][2]uint32
}

// segmentFrame builds an Ethernet/IPv4/TCP frame of s, with the ACK flag.
func segmentFrame(t *testing.T, s segment) []byte {
	t.Helper()
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(s.src.Port()),
		DstPort: layers.TCPPort(s.dst.Port()),
		Seq:     s.seq,
		Ack:     s.ack,
		ACK:     true,
		Window:  65535,
	}
	if len(s.sack) > 0 {
		data := make([]byte, 0, 8*len(s.sack))
		for _, b := range s.sack {
			data = binary.BigEndian.AppendUint32(data, b[0])
			data = binary.BigEndian.AppendUint32(data, b[1])
		}
		tcp.Options = []layers.TCPOption{
			{OptionType: layers.TCPOptionKindNop, OptionLength: 1},
			{OptionType: layers.TCPOptionKindNop, OptionLength: 1},
			{
				OptionType:   layers.TCPOptionKindSACK,
				OptionLength: uint8(2 + len(data)),
				OptionData:   data,
			},
		}
	}
	ip := &layers.IPv4{
		Version: 4, TTL: s.ttl, Protocol: layers.IPProtocolTCP,
		SrcIP: s.src.Addr().AsSlice(), DstIP: s.dst.Addr().AsSlice(),
	}
	require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0, 1, 2, 3, 4, 5},
		DstMAC:       net.HardwareAddr{6, 7, 8, 9, 10, 11},
		EthernetType: layers.EthernetTypeIPv4,
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	require.NoError(t, gopacket.SerializeLayers(buf, opts,
		eth, ip, tcp, gopacket.Payload(make([]byte, s.payload))))
	return buf.Bytes()
}

var testLocal = netip.MustParseAddrPort("192.0.2.1:40001")

func TestFlowWatch(t *testing.T) {
	src := newFakeSource(t)
	w := newFlowWatch(src)
	defer w.Close()

	flow := flowKey{server: testServer, localPort: testLocal.Port()}
	untrack := w.track(flow)

	other := netip.MustParseAddrPort("192.0.2.1:40002")
	src.frames <- segmentFrame(t, segment{src: other, dst: testServer, ttl: 64, seq: 1})
	src.frames <- segmentFrame(t, segment{src: testLocal, dst: testServer, ttl: 5, seq: 100, payload: 10})
	src.frames <- segmentFrame(t, segment{
		src: testServer, dst: testLocal, ttl: 50, ack: 100, sack: [][2]uint32{{110, 111}},
	})

	var got []flowSegment
	v := w.await(
		context.Background(),
		flow,
		5*time.Second,
		func(segs []flowSegment) verdict {
			if len(segs) < 2 {
				return undecided
			}
			got = segs
			return matched
		},
	)
	require.Equal(t, matched, v)
	require.Len(t, got, 2, "the other connection is not kept")
	assert.True(t, got[0].out)
	assert.Equal(t, uint8(5), got[0].TTL)
	assert.Equal(t, 10, got[0].PayloadLen)
	assert.False(t, got[1].out)
	assert.Equal(t, [][2]uint32{{110, 111}}, got[1].SACK)

	assert.Equal(t, failed, w.await(context.Background(), flow, time.Second,
		func([]flowSegment) verdict { return failed }))

	untrack()
	src.frames <- segmentFrame(t, segment{src: testLocal, dst: testServer, ttl: 5, seq: 110})
	assert.Equal(t, undecided, w.await(context.Background(), flow, 100*time.Millisecond,
		func(segs []flowSegment) verdict {
			if len(segs) > 0 {
				return matched
			}
			return undecided
		}), "an untracked connection is forgotten")
}

func TestFlowWatch_AwaitStopsOnContext(t *testing.T) {
	src := newFakeSource(t)
	w := newFlowWatch(src)
	defer w.Close()

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	start := time.Now()
	v := w.await(ctx, flowKey{server: testServer, localPort: 1}, time.Minute,
		func([]flowSegment) verdict { return undecided })
	assert.Equal(t, undecided, v)
	assert.Less(t, time.Since(start), 5*time.Second)
}

func TestFlowWatch_CloseClosesSource(t *testing.T) {
	src := newFakeSource(t)
	w := newFlowWatch(src)
	w.Close()
	assert.True(t, src.closed.Load())
}
