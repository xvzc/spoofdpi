package packet

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
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

// newTestHopStore returns a HopStore small enough for tests.
func newTestHopStore() *HopStore {
	return newHopStore(cache.NewLRUCache[HopKey, HopEntry](1, 16, nil))
}

func newTestSniffer(seqs *SeqTracker) *TCPSniffer {
	return &TCPSniffer{
		logger: zerolog.Nop(),
		hops:   newTestHopStore(),
		seqs:   seqs,
	}
}

func TestTCPSniffer_RecordsSeqFromSynAck(t *testing.T) {
	local := &net.TCPAddr{IP: net.ParseIP("192.168.1.11"), Port: 50000}
	remote := &net.TCPAddr{IP: net.ParseIP("203.0.113.1"), Port: 443}

	seqs := NewSeqTracker(time.Minute)
	ts := newTestSniffer(seqs)
	ts.hops.Register(ProtoTCP, []net.IP{remote.IP})

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
	entries := evictOnGetCache{cache.NewLRUCache[HopKey, HopEntry](1, 16, nil)}
	ts.hops = newHopStore(entries)
	ts.hops.Register(ProtoTCP, []net.IP{remote.IP})

	ts.processPacket(context.Background(), synAck(t, remote, local, 52, 7000, 1001))

	assert.False(t, entries.Has(HopKey{Proto: ProtoTCP, IP: netutil.NewIPKey(remote.IP)}))
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

// learnedHops returns the hop count s learned for ip over p, and whether
// it learned one.
func learnedHops(s *HopStore, p Proto, ip net.IP) (uint8, bool) {
	e, ok := s.entries.Get(HopKey{Proto: p, IP: netutil.NewIPKey(ip)})
	if !ok || !e.Learned {
		return 0, false
	}
	return e.Hops, true
}

func TestTCPSniffer_LearnsHops(t *testing.T) {
	local := &net.TCPAddr{IP: net.ParseIP("192.168.1.11"), Port: 50000}
	remote := &net.TCPAddr{IP: net.ParseIP("203.0.113.1"), Port: 443}

	ts := newTestSniffer(nil)
	ts.hops.Register(ProtoTCP, []net.IP{remote.IP})
	ts.processPacket(context.Background(), synAck(t, remote, local, 52, 7000, 1001))

	hops, ok := learnedHops(ts.hops, ProtoTCP, remote.IP)
	assert.True(t, ok)
	assert.Equal(t, uint8(12), hops)
	_, ok = learnedHops(ts.hops, ProtoUDP, remote.IP)
	assert.False(t, ok, "a SYN/ACK teaches the TCP hop count only")
}

func TestTCPSniffer_LearnsFromPrivateServer(t *testing.T) {
	local := &net.TCPAddr{IP: net.ParseIP("192.168.1.11"), Port: 50000}
	remote := &net.TCPAddr{IP: net.ParseIP("192.168.1.20"), Port: 443}

	seqs := NewSeqTracker(time.Minute)
	ts := newTestSniffer(seqs)
	ts.hops.Register(ProtoTCP, []net.IP{remote.IP})

	// A server on the local link: its TTL arrives unchanged.
	ts.processPacket(context.Background(), synAck(t, remote, local, 64, 7000, 1001))

	hops, ok := learnedHops(ts.hops, ProtoTCP, remote.IP)
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
	ts.hops.Register(ProtoTCP, []net.IP{remote.IP})

	ts.processPacket(context.Background(), synAck(t, remote, self, 7, 7000, 1001))

	_, ok := learnedHops(ts.hops, ProtoTCP, remote.IP)
	assert.False(t, ok)
	assert.Equal(t, 0, seqs.Len())
}

// sniffLogs returns the entries that processing packets with ts logged,
// after it replaced its logger with one that records them.
func sniffLogs(
	t *testing.T,
	ts *TCPSniffer,
	packets ...gopacket.Packet,
) []map[string]any {
	t.Helper()

	var log bytes.Buffer
	ts.logger = zerolog.New(&log).Level(zerolog.TraceLevel)
	for _, p := range packets {
		ts.processPacket(context.Background(), p)
	}
	return decodeLogs(t, &log)
}

func decodeLogs(t *testing.T, log *bytes.Buffer) []map[string]any {
	t.Helper()

	var entries []map[string]any
	lines := bufio.NewScanner(bytes.NewReader(log.Bytes()))
	for lines.Scan() {
		var entry map[string]any
		require.NoError(t, json.Unmarshal(lines.Bytes(), &entry))
		entries = append(entries, entry)
	}
	require.NoError(t, lines.Err())
	return entries
}

func TestTCPSniffer_LogsConnectionAddresses(t *testing.T) {
	local := &net.TCPAddr{IP: net.ParseIP("192.168.1.11"), Port: 54321}
	remote := &net.TCPAddr{IP: net.ParseIP("203.0.113.1"), Port: 443}

	ts := newTestSniffer(nil)
	ts.hops.Register(ProtoTCP, []net.IP{remote.IP})
	reply := synAck(t, remote, local, 52, 7000, 1001)

	entries := sniffLogs(t, ts, reply, reply)

	require.Len(t, entries, 2)
	assert.Equal(t, "ttl(tcp) update", entries[0]["message"])
	assert.Equal(t, "203.0.113.1:443", entries[0]["src"])
	assert.Equal(t, "192.168.1.11:54321", entries[0]["dst"])
	assert.EqualValues(t, 12, entries[0]["nhops"])
	assert.EqualValues(t, 52, entries[0]["ttlLeft"])

	assert.Equal(t, "ttl(tcp) unchanged", entries[1]["message"])
	assert.Equal(t, "192.168.1.11:54321", entries[1]["dst"])
}

func TestTCPSniffer_LogsIgnoredSynAck(t *testing.T) {
	local := &net.TCPAddr{IP: net.ParseIP("192.168.1.11"), Port: 54321}
	remote := &net.TCPAddr{IP: net.ParseIP("203.0.113.1"), Port: 443}

	entries := sniffLogs(
		t, newTestSniffer(nil), synAck(t, remote, local, 52, 7000, 1001),
	)

	require.Len(t, entries, 1)
	assert.Equal(t, "ttl(tcp) ignored, destination not registered", entries[0]["message"])
	assert.Equal(t, "203.0.113.1:443", entries[0]["src"])
	assert.Equal(t, "192.168.1.11:54321", entries[0]["dst"])
}
