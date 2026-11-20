package packet

import (
	"context"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/cache"
	"github.com/xvzc/spoofdpi/internal/netutil"
)

// udpPacket builds an Ethernet/IPv4/UDP packet from src to dst.
func udpPacket(t *testing.T, src, dst net.IP, ttl uint8) gopacket.Packet {
	t.Helper()

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0, 1, 2, 3, 4, 5},
		DstMAC:       net.HardwareAddr{6, 7, 8, 9, 10, 11},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      ttl,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    src.To4(),
		DstIP:    dst.To4(),
	}
	udp := &layers.UDP{SrcPort: 443, DstPort: 50000}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	require.NoError(
		t,
		gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload("x")),
	)

	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func TestUDPSniffer_LearnsHops(t *testing.T) {
	tcs := []struct {
		name     string
		server   string
		local    string
		ttl      uint8
		register bool
		wantOK   bool
		wantHops uint8
	}{
		{
			"public server, private local address",
			"203.0.113.1",
			"192.168.1.11",
			52,
			true,
			true,
			12,
		},
		{
			"public server, public local address",
			"203.0.113.1",
			"198.51.100.7",
			52,
			true,
			true,
			12,
		},
		{
			"private server on the local link",
			"192.168.1.20",
			"192.168.1.11",
			64,
			true,
			true,
			0,
		},
		{
			"unregistered server is ignored",
			"203.0.113.1",
			"192.168.1.11",
			52,
			false,
			false,
			0,
		},
		{
			// A packet from the server's address to itself, like a fake
			// spoofing the server, must not be learned as a reply.
			"packet to itself is ignored",
			"203.0.113.1",
			"203.0.113.1",
			7,
			true,
			false,
			0,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			us := &UDPSniffer{
				logger:     zerolog.Nop(),
				nhopCache:  cache.NewLRUCache[netutil.IPKey, HopEntry](1, 16, nil),
				defaultTTL: 8,
			}
			server := net.ParseIP(tc.server)
			if tc.register {
				us.Register([]net.IP{server})
			}

			us.processPacket(
				context.Background(),
				udpPacket(t, server, net.ParseIP(tc.local), tc.ttl),
			)

			hops, ok := us.LearnedHops(netutil.NewIPKey(server))
			assert.Equal(t, tc.wantOK, ok)
			assert.Equal(t, tc.wantHops, hops)
		})
	}
}
