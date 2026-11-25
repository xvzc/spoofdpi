package packet

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"syscall"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/packetio/inject"
	"github.com/xvzc/spoofdpi/internal/packetio/inject/injecttest"
)

// testSenders returns Senders with a recording sender for each family.
func testSenders() (Senders, *injecttest.Sender, *injecttest.Sender) {
	v4, v6 := &injecttest.Sender{}, &injecttest.Sender{}
	return Senders{V4: v4, V6: v6}, v4, v6
}

// sentPacket returns the one packet that v4 or v6 was given.
func sentPacket(t *testing.T, v4, v6 *injecttest.Sender) inject.Packet {
	t.Helper()
	sent := append(v4.Packets(), v6.Packets()...)
	require.Len(t, sent, 1)
	return sent[0]
}

func writeFake(
	t *testing.T,
	src, dst string,
	fake TCPFake,
) (*layers.TCP, inject.Packet) {
	t.Helper()

	senders, v4, v6 := testSenders()
	w := NewTCPWriter(zerolog.Nop(), senders)

	n, err := w.WriteCraftedPacketWithSeq(
		context.Background(),
		&net.TCPAddr{IP: net.ParseIP(src), Port: 50000},
		&net.TCPAddr{IP: net.ParseIP(dst), Port: 443},
		8,
		[]byte("payload"),
		fake,
	)
	require.NoError(t, err)
	assert.Equal(t, len("payload"), n)

	p := sentPacket(t, v4, v6)
	sender := v4
	if p.Dst.Is6() {
		sender = v6
	}
	assert.Len(t, sender.Packets(), 1, "sent through the sender of dst's family")
	assert.Equal(t, netip.MustParseAddr(src), p.Src)
	assert.Equal(t, netip.MustParseAddr(dst), p.Dst)
	assert.Equal(t, uint8(6), p.Proto)
	assert.Equal(t, uint8(8), p.HopLimit, "the TTL goes in the packet")

	pkt := gopacket.NewPacket(p.L4, layers.LayerTypeTCP, gopacket.Default)
	tcp, ok := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
	require.True(t, ok)
	assert.Equal(t, layers.TCPPort(50000), tcp.SrcPort)
	assert.Equal(t, layers.TCPPort(443), tcp.DstPort)
	assert.True(t, tcp.PSH)
	assert.True(t, tcp.ACK)
	assert.False(t, tcp.SYN || tcp.FIN || tcp.RST || tcp.URG)
	assert.Equal(t, uint16(12345), tcp.Window)
	return tcp, p
}

// l4ChecksumValid reports whether the transport checksum of p is valid
// over its IPv4 or IPv6 pseudo-header.
func l4ChecksumValid(p inject.Packet) bool {
	var sum uint32
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i:]))
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	add(p.Src.AsSlice())
	add(p.Dst.AsSlice())
	sum += uint32(p.Proto) + uint32(len(p.L4))
	add(p.L4)
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return sum == 0xffff
}

func TestTCPWriter_BadMD5Sig(t *testing.T) {
	for name, addrs := range map[string][2]string{
		"ipv4": {"192.0.2.1", "203.0.113.1"},
		"ipv6": {"2001:db8::1", "2001:db8::2"},
	} {
		t.Run(name, func(t *testing.T) {
			seq := SeqAck{Seq: 1000, Ack: 5000}

			tcp, p := writeFake(
				t,
				addrs[0],
				addrs[1],
				TCPFake{SeqAck: seq, BadMD5Sig: true},
			)
			assert.Equal(t, uint32(1000), tcp.Seq)
			assert.Equal(t, uint32(5000), tcp.Ack)
			assert.Equal(t, uint8((20+MD5SigOptionLen)/4), tcp.DataOffset,
				"header grows by MD5SigOptionLen")
			require.Len(t, tcp.Options, 3)
			assert.Equal(
				t,
				layers.TCPOptionKind(layers.TCPOptionKindNop),
				tcp.Options[0].OptionType,
			)
			assert.Equal(
				t,
				layers.TCPOptionKind(layers.TCPOptionKindNop),
				tcp.Options[1].OptionType,
			)
			md5 := tcp.Options[2]
			assert.Equal(t, layers.TCPOptionKind(19), md5.OptionType)
			assert.Equal(t, uint8(18), md5.OptionLength)
			assert.Len(t, md5.OptionData, 16)
			assert.Equal(t, []byte("payload"), tcp.Payload)
			assert.Len(t, p.L4, 20+MD5SigOptionLen+len("payload"))
			assert.True(t, l4ChecksumValid(p))

			other, _ := writeFake(
				t,
				addrs[0],
				addrs[1],
				TCPFake{SeqAck: seq, BadMD5Sig: true},
			)
			assert.NotEqual(t, md5.OptionData, other.Options[2].OptionData,
				"each packet gets a random digest")

			plain, p := writeFake(t, addrs[0], addrs[1], TCPFake{SeqAck: seq})
			assert.Empty(t, plain.Options)
			assert.Equal(t, uint8(5), plain.DataOffset)
			assert.True(t, l4ChecksumValid(p))
		})
	}
}

func TestTCPWriter_RandomSeq(t *testing.T) {
	senders, v4, _ := testSenders()
	w := NewTCPWriter(zerolog.Nop(), senders)
	src := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 50000}
	dst := &net.TCPAddr{IP: net.ParseIP("203.0.113.1"), Port: 443}
	for range 2 {
		_, err := w.WriteCraftedPacket(context.Background(), src, dst, 3, []byte("x"))
		require.NoError(t, err)
	}

	sent := v4.Packets()
	require.Len(t, sent, 2)
	var seqs []uint32
	for _, p := range sent {
		assert.Equal(t, uint8(3), p.HopLimit)
		assert.True(t, l4ChecksumValid(p))
		seqs = append(seqs, binary.BigEndian.Uint32(p.L4[4:]))
	}
	assert.NotEqual(t, seqs[0], seqs[1], "each packet gets random numbers")
}

func TestTCPWriter_IPv4MappedSource(t *testing.T) {
	senders, v4, _ := testSenders()
	w := NewTCPWriter(zerolog.Nop(), senders)
	_, err := w.WriteCraftedPacketWithSeq(
		context.Background(),
		&net.TCPAddr{IP: net.ParseIP("192.0.2.1").To16(), Port: 50000},
		&net.TCPAddr{IP: net.ParseIP("203.0.113.1").To4(), Port: 443},
		8,
		nil,
		TCPFake{},
	)
	require.NoError(t, err)
	p := sentPacket(t, v4, &injecttest.Sender{})
	assert.Equal(t, netip.MustParseAddr("192.0.2.1"), p.Src)
	assert.Equal(t, netip.MustParseAddr("203.0.113.1"), p.Dst)
	assert.True(t, l4ChecksumValid(p))
}

func TestTCPWriter_Errors(t *testing.T) {
	v4src := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 50000}
	v4dst := &net.TCPAddr{IP: net.ParseIP("203.0.113.1"), Port: 443}
	v6dst := &net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 443}
	ctx := context.Background()

	t.Run("no sender for the family", func(t *testing.T) {
		v4 := &injecttest.Sender{}
		w := NewTCPWriter(zerolog.Nop(), Senders{V4: v4})
		v6src := &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 50000}
		n, err := w.WriteCraftedPacket(ctx, v6src, v6dst, 8, []byte("x"))
		require.ErrorContains(t, err, "no ipv6 sender")
		assert.Zero(t, n)
		assert.Empty(t, v4.Packets())
	})

	t.Run("hop limit 0", func(t *testing.T) {
		senders, v4, _ := testSenders()
		w := NewTCPWriter(zerolog.Nop(), senders)
		n, err := w.WriteCraftedPacket(ctx, v4src, v4dst, 0, []byte("x"))
		require.ErrorContains(t, err, "hop limit 0")
		assert.Zero(t, n)
		assert.Empty(t, v4.Packets())
	})

	t.Run("families differ", func(t *testing.T) {
		senders, v4, v6 := testSenders()
		w := NewTCPWriter(zerolog.Nop(), senders)
		_, err := w.WriteCraftedPacket(ctx, v4src, v6dst, 8, []byte("x"))
		require.ErrorContains(t, err, "differ in family")
		assert.Empty(t, append(v4.Packets(), v6.Packets()...))
	})

	t.Run("not TCP addresses", func(t *testing.T) {
		senders, _, _ := testSenders()
		w := NewTCPWriter(zerolog.Nop(), senders)
		udp := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1}
		_, err := w.WriteCraftedPacket(ctx, udp, v4dst, 8, nil)
		require.Error(t, err)
		_, err = w.WriteCraftedPacket(ctx, v4src, udp, 8, nil)
		require.Error(t, err)
	})

	t.Run("send fails", func(t *testing.T) {
		senders, v4, _ := testSenders()
		v4.SetErr(syscall.EPERM)
		w := NewTCPWriter(zerolog.Nop(), senders)
		n, err := w.WriteCraftedPacket(ctx, v4src, v4dst, 8, []byte("x"))
		var sendErr *inject.SendError
		require.ErrorAs(t, err, &sendErr)
		assert.Equal(t, inject.KindBlocked, sendErr.Kind)
		assert.Zero(t, n)
	})
}
