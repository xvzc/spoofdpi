package packet

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/cache"
	"github.com/xvzc/spoofdpi/internal/netutil"
)

// synAck builds an Ethernet/IPv4/TCP SYN/ACK sent from server to client.
func synAck(
	t *testing.T,
	server, client *net.TCPAddr,
	seq, ack uint32,
) gopacket.Packet {
	t.Helper()

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0, 1, 2, 3, 4, 5},
		DstMAC:       net.HardwareAddr{6, 7, 8, 9, 10, 11},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      52,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    server.IP.To4(),
		DstIP:    client.IP.To4(),
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(server.Port),
		DstPort: layers.TCPPort(client.Port),
		Seq:     seq,
		Ack:     ack,
		SYN:     true,
		ACK:     true,
		Window:  65535,
	}
	require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	require.NoError(t, gopacket.SerializeLayers(buf, opts, eth, ip, tcp))

	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func newTestSniffer(seqs *SeqTracker) *TCPSniffer {
	return &TCPSniffer{
		logger:     zerolog.Nop(),
		nhopCache:  cache.NewLRUCache[netutil.IPKey, uint8](1, 16, nil),
		defaultTTL: 8,
		seqs:       seqs,
	}
}

func TestTCPSniffer_RecordsSeqFromSynAck(t *testing.T) {
	local := &net.TCPAddr{IP: net.ParseIP("192.168.1.11"), Port: 50000}
	remote := &net.TCPAddr{IP: net.ParseIP("203.0.113.1"), Port: 443}

	seqs := NewSeqTracker(time.Minute)
	ts := newTestSniffer(seqs)
	ts.Register([]net.IP{remote.IP})

	ts.processPacket(context.Background(), synAck(t, remote, local, 7000, 1001))

	// The key Desync builds from the connection's addresses must match the
	// one the sniffer builds from the SYN/ACK.
	seq, ok := seqs.Wait(context.Background(), SeqKey(local, remote), 10*time.Millisecond)
	require.True(t, ok)
	assert.Equal(t, TCPSeq{Seq: 1001, Ack: 7001}, seq)
}

func TestTCPSniffer_IgnoresUnregisteredServer(t *testing.T) {
	local := &net.TCPAddr{IP: net.ParseIP("192.168.1.11"), Port: 50000}
	remote := &net.TCPAddr{IP: net.ParseIP("203.0.113.1"), Port: 443}

	seqs := NewSeqTracker(time.Minute)
	ts := newTestSniffer(seqs)

	ts.processPacket(context.Background(), synAck(t, remote, local, 7000, 1001))

	assert.Equal(t, 0, seqs.Len())
}

func TestCanLearnSeq(t *testing.T) {
	tcs := []struct {
		ip   string
		want bool
	}{
		{"203.0.113.1", true},
		{"8.8.8.8", true},
		{"192.168.1.1", false},
		{"10.0.0.1", false},
		{"172.16.0.1", false},
		{"127.0.0.1", false},
		{"2001:db8::1", false},
	}

	for _, tc := range tcs {
		t.Run(tc.ip, func(t *testing.T) {
			assert.Equal(t, tc.want, CanLearnSeq(net.ParseIP(tc.ip)))
		})
	}
}
