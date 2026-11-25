package desync

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUDPWriter(t *testing.T) {
	for name, addrs := range map[string][2]string{
		"ipv4": {"192.0.2.1", "203.0.113.1"},
		"ipv6": {"2001:db8::1", "2001:db8::2"},
	} {
		t.Run(name, func(t *testing.T) {
			senders, v4, v6 := testSenders()
			w := NewUDPWriter(zerolog.Nop(), senders)
			n, err := w.WriteCraftedPacket(
				context.Background(),
				&net.UDPAddr{IP: net.ParseIP(addrs[0]), Port: 50000},
				&net.UDPAddr{IP: net.ParseIP(addrs[1]), Port: 443},
				5,
				[]byte("quic"),
			)
			require.NoError(t, err)
			assert.Equal(t, len("quic"), n)

			p := sentPacket(t, v4, v6)
			assert.Equal(t, netip.MustParseAddr(addrs[0]), p.Src)
			assert.Equal(t, netip.MustParseAddr(addrs[1]), p.Dst)
			assert.Equal(t, uint8(17), p.Proto)
			assert.Equal(t, uint8(5), p.HopLimit)
			assert.True(t, l4ChecksumValid(p))

			pkt := gopacket.NewPacket(p.L4, layers.LayerTypeUDP, gopacket.Default)
			udp, ok := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
			require.True(t, ok)
			assert.Equal(t, layers.UDPPort(50000), udp.SrcPort)
			assert.Equal(t, layers.UDPPort(443), udp.DstPort)
			assert.Equal(t, uint16(8+len("quic")), udp.Length)
			assert.Equal(t, []byte("quic"), udp.Payload)
		})
	}
}

func TestUDPWriter_Errors(t *testing.T) {
	w := NewUDPWriter(zerolog.Nop(), Senders{})
	src := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 50000}
	dst := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 443}
	_, err := w.WriteCraftedPacket(context.Background(), src, dst, 5, nil)
	require.ErrorContains(t, err, "no ipv4 sender")

	tcp := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1}
	_, err = w.WriteCraftedPacket(context.Background(), tcp, dst, 5, nil)
	require.Error(t, err)
}
