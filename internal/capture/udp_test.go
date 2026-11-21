package capture

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// udpPacket builds an Ethernet/IP/UDP packet from src to dst; the IP
// version follows the addresses.
func udpPacket(t *testing.T, src, dst *net.UDPAddr, ttl uint8) gopacket.Packet {
	t.Helper()

	udp := &layers.UDP{
		SrcPort: layers.UDPPort(src.Port),
		DstPort: layers.UDPPort(dst.Port),
	}
	eth := &layers.Ethernet{
		SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5},
		DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11},
	}
	var ip gopacket.SerializableLayer
	if src.IP.To4() != nil {
		eth.EthernetType = layers.EthernetTypeIPv4
		ip4 := &layers.IPv4{
			Version:  4,
			TTL:      ttl,
			Protocol: layers.IPProtocolUDP,
			SrcIP:    src.IP.To4(),
			DstIP:    dst.IP.To4(),
		}
		require.NoError(t, udp.SetNetworkLayerForChecksum(ip4))
		ip = ip4
	} else {
		eth.EthernetType = layers.EthernetTypeIPv6
		ip6 := &layers.IPv6{
			Version:    6,
			HopLimit:   ttl,
			NextHeader: layers.IPProtocolUDP,
			SrcIP:      src.IP,
			DstIP:      dst.IP,
		}
		require.NoError(t, udp.SetNetworkLayerForChecksum(ip6))
		ip = ip6
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	require.NoError(
		t,
		gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload("x")),
	)
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func TestParseUDP(t *testing.T) {
	server4 := &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 443}
	client4 := &net.UDPAddr{IP: net.ParseIP("192.168.0.2"), Port: 50000}
	server6 := &net.UDPAddr{IP: net.ParseIP("2001:db8::7"), Port: 443}
	client6 := &net.UDPAddr{IP: net.ParseIP("2001:db8::2"), Port: 50000}

	t.Run("ipv4", func(t *testing.T) {
		u, ok := ParseUDP(udpPacket(t, server4, client4, 50))
		require.True(t, ok)
		assert.True(t, server4.IP.Equal(u.Src))
		assert.True(t, client4.IP.Equal(u.Dst))
		assert.Equal(t, uint16(443), u.SrcPort)
		assert.Equal(t, uint16(50000), u.DstPort)
		assert.Equal(t, uint8(50), u.TTLLeft)
		assert.Equal(t, uint8(14), u.Hops)
	})

	t.Run("ipv6", func(t *testing.T) {
		u, ok := ParseUDP(udpPacket(t, server6, client6, 120))
		require.True(t, ok)
		assert.True(t, server6.IP.Equal(u.Src))
		assert.True(t, client6.IP.Equal(u.Dst))
		assert.Equal(t, uint16(443), u.SrcPort)
		assert.Equal(t, uint16(50000), u.DstPort)
		assert.Equal(t, uint8(120), u.TTLLeft)
		assert.Equal(t, uint8(8), u.Hops)
	})

	t.Run("rejects self-addressed ipv4", func(t *testing.T) {
		_, ok := ParseUDP(udpPacket(t, server4, server4, 50))
		assert.False(t, ok)
	})

	t.Run("rejects self-addressed ipv6", func(t *testing.T) {
		_, ok := ParseUDP(udpPacket(t, server6, server6, 50))
		assert.False(t, ok)
	})

	t.Run("rejects non-udp", func(t *testing.T) {
		p := tcpPacket(
			t,
			&net.TCPAddr{IP: server4.IP, Port: 443},
			&net.TCPAddr{IP: client4.IP, Port: 50000},
			50,
			true,
			true,
		)
		_, ok := ParseUDP(p)
		assert.False(t, ok)
	})
}

// TestUDPFilter pins the BPF programs emitted for each link type: those
// spoofdpi's UDP sniffer has always captured with.
func TestUDPFilter(t *testing.T) {
	// The IPv4 version check of the non-Ethernet link types, then the rest.
	nonEthernet := func(base uint32) []BPFInstruction {
		return []BPFInstruction{
			{Op: 0x30, Jt: 0, Jf: 0, K: base},
			{Op: 0x54, Jt: 0, Jf: 0, K: 0xf0},
			{Op: 0x15, Jt: 0, Jf: 3, K: 0x40},
			{Op: 0x30, Jt: 0, Jf: 0, K: base + 9},
			{Op: 0x15, Jt: 0, Jf: 1, K: 17},
			{Op: 0x06, Jt: 0, Jf: 0, K: 0x40000},
			{Op: 0x06, Jt: 0, Jf: 0, K: 0x0},
		}
	}

	tcs := []struct {
		linkType layers.LinkType
		want     []BPFInstruction
	}{
		{
			layers.LinkTypeEthernet,
			[]BPFInstruction{
				{Op: 0x28, Jt: 0, Jf: 0, K: 12},
				{Op: 0x15, Jt: 0, Jf: 3, K: 0x800},
				{Op: 0x30, Jt: 0, Jf: 0, K: 23},
				{Op: 0x15, Jt: 0, Jf: 1, K: 17},
				{Op: 0x06, Jt: 0, Jf: 0, K: 0x40000},
				{Op: 0x06, Jt: 0, Jf: 0, K: 0x0},
			},
		},
		{layers.LinkTypeNull, nonEthernet(4)},
		{layers.LinkTypeLoop, nonEthernet(4)},
		{layers.LinkTypeRaw, nonEthernet(0)},
	}
	for _, tc := range tcs {
		t.Run(tc.linkType.String(), func(t *testing.T) {
			assert.Equal(t, tc.want, UDPFilter(tc.linkType))
		})
	}
}
