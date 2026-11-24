package capture

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tcpPacket builds an Ethernet/IP/TCP packet from src to dst; the IP
// version follows the addresses.
func tcpPacket(
	t *testing.T,
	src, dst *net.TCPAddr,
	ttl uint8,
	syn, ack bool,
) gopacket.Packet {
	t.Helper()

	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(src.Port),
		DstPort: layers.TCPPort(dst.Port),
		Seq:     1000,
		Ack:     2000,
		SYN:     syn,
		ACK:     ack,
		Window:  65535,
	}

	var ip gopacket.SerializableLayer
	eth := &layers.Ethernet{
		SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5},
		DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11},
	}
	if src.IP.To4() != nil {
		eth.EthernetType = layers.EthernetTypeIPv4
		ip4 := &layers.IPv4{
			Version:  4,
			TTL:      ttl,
			Protocol: layers.IPProtocolTCP,
			SrcIP:    src.IP.To4(),
			DstIP:    dst.IP.To4(),
		}
		require.NoError(t, tcp.SetNetworkLayerForChecksum(ip4))
		ip = ip4
	} else {
		eth.EthernetType = layers.EthernetTypeIPv6
		ip6 := &layers.IPv6{
			Version:    6,
			HopLimit:   ttl,
			NextHeader: layers.IPProtocolTCP,
			SrcIP:      src.IP,
			DstIP:      dst.IP,
		}
		require.NoError(t, tcp.SetNetworkLayerForChecksum(ip6))
		ip = ip6
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	require.NoError(t, gopacket.SerializeLayers(buf, opts, eth, ip, tcp))

	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func TestParseSynAck(t *testing.T) {
	server4 := &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 443}
	client4 := &net.TCPAddr{IP: net.ParseIP("192.168.0.2"), Port: 50000}
	server6 := &net.TCPAddr{IP: net.ParseIP("2001:db8::7"), Port: 443}
	client6 := &net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 50000}

	t.Run("ipv4", func(t *testing.T) {
		sa, ok := ParseSynAck(tcpPacket(t, server4, client4, 50, true, true))
		require.True(t, ok)
		assert.True(t, server4.IP.Equal(sa.Src))
		assert.True(t, client4.IP.Equal(sa.Dst))
		assert.Equal(t, uint16(443), sa.SrcPort)
		assert.Equal(t, uint16(50000), sa.DstPort)
		assert.Equal(t, uint32(1000), sa.Seq)
		assert.Equal(t, uint32(2000), sa.Ack)
		assert.Equal(t, uint8(50), sa.TTLLeft)
		assert.Equal(t, uint8(14), sa.Hops)
	})

	t.Run("ipv6", func(t *testing.T) {
		sa, ok := ParseSynAck(tcpPacket(t, server6, client6, 120, true, true))
		require.True(t, ok)
		assert.True(t, server6.IP.Equal(sa.Src))
		assert.True(t, client6.IP.Equal(sa.Dst))
		assert.Equal(t, uint16(443), sa.SrcPort)
		assert.Equal(t, uint16(50000), sa.DstPort)
		assert.Equal(t, uint8(120), sa.TTLLeft)
		assert.Equal(t, uint8(8), sa.Hops)
	})

	// A PPP frame travels with or without the HDLC address and control
	// bytes, and gopacket decodes both.
	t.Run("ppp", func(t *testing.T) {
		ip := ipv4TCP(t, true, true)
		for _, hdlc := range []bool{true, false} {
			frame, ok := onLink(
				layers.LinkTypePPP,
				hdlc,
				filterFrame{etherType: layers.EthernetTypeIPv4, payload: ip},
			)
			require.True(t, ok)

			sa, ok := ParseSynAck(
				gopacket.NewPacket(frame, layers.LinkTypePPP, gopacket.Default),
			)
			require.True(t, ok, "hdlc=%v", hdlc)
			assert.True(t, filterSrc4.Equal(sa.Src))
			assert.True(t, filterDst4.Equal(sa.Dst))
			assert.Equal(t, uint32(1000), sa.Seq)
			assert.Equal(t, uint32(2000), sa.Ack)
			assert.Equal(t, uint8(50), sa.TTLLeft)
			assert.Equal(t, uint8(14), sa.Hops)
		}
	})

	rejects := []struct {
		name     string
		src, dst *net.TCPAddr
		syn, ack bool
	}{
		{"syn only", server4, client4, true, false},
		{"ack only", server4, client4, false, true},
		{"self-addressed ipv4", server4, server4, true, true},
		{"self-addressed ipv6", server6, server6, true, true},
	}
	for _, tc := range rejects {
		t.Run("rejects "+tc.name, func(t *testing.T) {
			_, ok := ParseSynAck(tcpPacket(t, tc.src, tc.dst, 50, tc.syn, tc.ack))
			assert.False(t, ok)
		})
	}

	t.Run("rejects non-tcp", func(t *testing.T) {
		buf := gopacket.NewSerializeBuffer()
		require.NoError(t, gopacket.SerializeLayers(buf,
			gopacket.SerializeOptions{FixLengths: true},
			&layers.Ethernet{
				SrcMAC:       net.HardwareAddr{0, 1, 2, 3, 4, 5},
				DstMAC:       net.HardwareAddr{6, 7, 8, 9, 10, 11},
				EthernetType: layers.EthernetTypeIPv4,
			},
			&layers.IPv4{
				Version:  4,
				TTL:      64,
				Protocol: layers.IPProtocolUDP,
				SrcIP:    server4.IP.To4(),
				DstIP:    client4.IP.To4(),
			},
			&layers.UDP{SrcPort: 53, DstPort: 50000},
		))
		p := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
		_, ok := ParseSynAck(p)
		assert.False(t, ok)
	})
}

func TestEstimateHops(t *testing.T) {
	tcs := []struct {
		ttlLeft uint8
		want    uint8
	}{
		{0, 64},
		{1, 63},
		{64, 0},
		{65, 63},
		{128, 0},
		{129, 126},
		{255, 0},
	}
	for _, tc := range tcs {
		assert.Equal(t, tc.want, EstimateHops(tc.ttlLeft), "ttlLeft=%d", tc.ttlLeft)
	}
}
