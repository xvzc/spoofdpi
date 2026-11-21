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
	ttl uint8,
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
		TTL:      ttl,
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
		logger:    zerolog.Nop(),
		nhopCache: cache.NewLRUCache[netutil.IPKey, HopEntry](1, 16, nil),
		seqs:      seqs,
	}
}

func TestTCPSniffer_RecordsSeqFromSynAck(t *testing.T) {
	local := &net.TCPAddr{IP: net.ParseIP("192.168.1.11"), Port: 50000}
	remote := &net.TCPAddr{IP: net.ParseIP("203.0.113.1"), Port: 443}

	seqs := NewSeqTracker(time.Minute)
	ts := newTestSniffer(seqs)
	ts.Register([]net.IP{remote.IP})

	ts.processPacket(context.Background(), synAck(t, remote, local, 52, 7000, 1001))

	// The key Desync builds from the connection's addresses must match the
	// one the sniffer builds from the SYN/ACK.
	seq, ok := seqs.Wait(context.Background(), SeqKey(local, remote), 10*time.Millisecond)
	require.True(t, ok)
	assert.Equal(t, SeqAck{Seq: 1001, Ack: 7001}, seq)
}

func TestTCPSniffer_IgnoresUnregisteredServer(t *testing.T) {
	local := &net.TCPAddr{IP: net.ParseIP("192.168.1.11"), Port: 50000}
	remote := &net.TCPAddr{IP: net.ParseIP("203.0.113.1"), Port: 443}

	seqs := NewSeqTracker(time.Minute)
	ts := newTestSniffer(seqs)

	ts.processPacket(context.Background(), synAck(t, remote, local, 52, 7000, 1001))

	assert.Equal(t, 0, seqs.Len())
}

func TestTCPSniffer_DoesNotReinsertEvictedServer(t *testing.T) {
	local := &net.TCPAddr{IP: net.ParseIP("192.168.1.11"), Port: 50000}
	remote := &net.TCPAddr{IP: net.ParseIP("203.0.113.1"), Port: 443}

	seqs := NewSeqTracker(time.Minute)
	ts := newTestSniffer(seqs)
	ts.nhopCache = evictOnGetCache{ts.nhopCache}
	ts.Register([]net.IP{remote.IP})

	ts.processPacket(context.Background(), synAck(t, remote, local, 52, 7000, 1001))

	assert.False(t, ts.nhopCache.Has(netutil.NewIPKey(remote.IP)))
	assert.Equal(t, 0, seqs.Len())
}

func TestCanLearnSeq(t *testing.T) {
	tcs := []struct {
		ip   string
		want bool
	}{
		{"203.0.113.1", true},
		{"8.8.8.8", true},
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"2001:db8::1", false},
	}

	for _, tc := range tcs {
		t.Run(tc.ip, func(t *testing.T) {
			assert.Equal(t, tc.want, CanLearnSeq(net.ParseIP(tc.ip)))
		})
	}
}

// learnedHops returns the hop count s learned for key, and whether it
// learned one.
func learnedHops(s Sniffer, key netutil.IPKey) (uint8, bool) {
	e, ok := s.Hops(key)
	if !ok || !e.Learned {
		return 0, false
	}
	return e.Hops, true
}

func TestTCPSniffer_Hops(t *testing.T) {
	local := &net.TCPAddr{IP: net.ParseIP("192.168.1.11"), Port: 50000}
	remote := &net.TCPAddr{IP: net.ParseIP("203.0.113.1"), Port: 443}
	key := netutil.NewIPKey(remote.IP)

	ts := newTestSniffer(nil)
	_, ok := ts.Hops(key)
	assert.False(t, ok, "unknown server")

	ts.Register([]net.IP{remote.IP})
	e, ok := ts.Hops(key)
	assert.True(t, ok, "registered server is cached")
	assert.Equal(t, HopEntry{}, e, "registered server has no hop count until learned")

	ts.processPacket(context.Background(), synAck(t, remote, local, 52, 7000, 1001))
	e, ok = ts.Hops(key)
	assert.True(t, ok)
	assert.Equal(t, HopEntry{Hops: 12, Learned: true}, e)

	ts.Register([]net.IP{remote.IP})
	e, _ = ts.Hops(key)
	assert.Equal(
		t,
		HopEntry{Hops: 12, Learned: true},
		e,
		"registering again keeps the learned value",
	)
}

func TestTCPSniffer_LearnsFromPrivateServer(t *testing.T) {
	local := &net.TCPAddr{IP: net.ParseIP("192.168.1.11"), Port: 50000}
	remote := &net.TCPAddr{IP: net.ParseIP("192.168.1.20"), Port: 443}

	seqs := NewSeqTracker(time.Minute)
	ts := newTestSniffer(seqs)
	ts.Register([]net.IP{remote.IP})

	// A server on the local link: its TTL arrives unchanged.
	ts.processPacket(context.Background(), synAck(t, remote, local, 64, 7000, 1001))

	hops, ok := learnedHops(ts, netutil.NewIPKey(remote.IP))
	assert.True(t, ok)
	assert.Equal(t, uint8(0), hops)

	seq, ok := seqs.Wait(context.Background(), SeqKey(local, remote), 10*time.Millisecond)
	require.True(t, ok)
	assert.Equal(t, SeqAck{Seq: 1001, Ack: 7001}, seq)
}

func TestTCPSniffer_IgnoresPacketToItself(t *testing.T) {
	remote := &net.TCPAddr{IP: net.ParseIP("203.0.113.1"), Port: 443}
	self := &net.TCPAddr{IP: net.ParseIP("203.0.113.1"), Port: 50000}

	seqs := NewSeqTracker(time.Minute)
	ts := newTestSniffer(seqs)
	ts.Register([]net.IP{remote.IP})

	ts.processPacket(context.Background(), synAck(t, remote, self, 7, 7000, 1001))

	_, ok := learnedHops(ts, netutil.NewIPKey(remote.IP))
	assert.False(t, ok)
	assert.Equal(t, 0, seqs.Len())
}
