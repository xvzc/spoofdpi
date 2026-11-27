package desync

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/packetio/inject/injecttest"
)

// familyAddrs are a local and a server address of each address family.
var familyAddrs = map[string][2]string{
	"ipv4": {"192.168.1.11", "203.0.113.1"},
	"ipv6": {"2001:db8::11", "2001:db8:1::1"},
}

// familySenders returns the sender that the packets to server go through,
// and the other one, which must stay unused.
func familySenders(
	server net.IP,
	v4, v6 *injecttest.Sender,
) (used, unused *injecttest.Sender) {
	if server.To4() != nil {
		return v4, v6
	}
	return v6, v4
}

// TestTLSDesync_FakesPerFamily checks the TLS fake path of each family,
// from the SYN/ACK the sniffer learns to the packets the sender is given:
// the fakes carry the learned sequence numbers and a hop limit from the
// learned hop count, and leave through the sender of their family.
func TestTLSDesync_FakesPerFamily(t *testing.T) {
	for name, addrs := range familyAddrs {
		t.Run(name, func(t *testing.T) {
			local := &net.TCPAddr{IP: net.ParseIP(addrs[0]), Port: 50000}
			remote := &net.TCPAddr{IP: net.ParseIP(addrs[1]), Port: 443}

			hops := newTestHopStore()
			seqs := NewSeqTracker(time.Minute)
			sniffer := &TCPSniffer{logger: zerolog.Nop(), hops: hops, seqs: seqs}
			senders, v4, v6 := testSenders()
			d := NewTLSDesyncer(
				zerolog.Nop(),
				NewTCPWriter(zerolog.Nop(), senders),
				hops,
				seqSource(seqs, bothFams),
				NewStaticGate(nil, nil),
			)
			opts := tlsOpts(1, 100)

			d.PrepareHopTrack([]net.IP{remote.IP}, opts)
			sniffer.processPacket(
				context.Background(),
				synAck(t, remote, local, 52, 7000, 1001),
			)

			n, err := d.Desync(
				context.Background(),
				&stubConn{local: local, remote: remote},
				fakeMsg(),
				opts,
				baseConnOpts(),
			)
			require.NoError(t, err)
			assert.Equal(t, len(config.FakeClientHello), n)

			used, unused := familySenders(remote.IP, v4, v6)
			assert.Empty(t, unused.Packets())
			sent := used.Packets()
			require.NotEmpty(t, sent)
			p := sent[0]
			assert.Equal(t, netip.MustParseAddr(addrs[0]), p.Src)
			assert.Equal(t, netip.MustParseAddr(addrs[1]), p.Dst)
			assert.Equal(t, uint8(11), p.HopLimit,
				"12 hops learned from 52 left of 64, plus hop-count-offset -1")
			assert.True(t, l4ChecksumValid(p))

			pkt := gopacket.NewPacket(p.L4, layers.LayerTypeTCP, gopacket.Default)
			tcp, ok := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
			require.True(t, ok)
			assert.Equal(t, uint32(1001), tcp.Seq, "the SYN/ACK's ack")
			assert.Equal(t, uint32(7001), tcp.Ack, "the SYN/ACK's seq plus 1")
		})
	}
}

// TestUDPDesync_FakesPerFamily checks the UDP fake path of each family,
// from the datagram the sniffer learns the hop count from to the packets
// the sender is given.
func TestUDPDesync_FakesPerFamily(t *testing.T) {
	for name, addrs := range familyAddrs {
		t.Run(name, func(t *testing.T) {
			local := &net.UDPAddr{IP: net.ParseIP(addrs[0]), Port: 50000}
			remote := &net.UDPAddr{IP: net.ParseIP(addrs[1]), Port: 443}

			hops := newTestHopStore()
			sniffer := &UDPSniffer{logger: zerolog.Nop(), hops: hops}
			senders, v4, v6 := testSenders()
			d := NewUDPDesyncer(
				zerolog.Nop(),
				NewUDPWriter(zerolog.Nop(), senders),
				hops,
				NewStaticGate(nil, nil),
			)
			opts := &config.UDPOptions{FakePreflight: 2, FakePacket: []byte("quic")}

			d.PrepareHopTrack([]net.IP{remote.IP}, opts)
			sniffer.processPacket(
				context.Background(),
				udpPacket(t, remote.IP, local.IP, 52),
			)

			n, err := d.Desync(
				context.Background(),
				udpConn{local: local, remote: remote},
				opts,
				baseConnOpts(),
			)
			require.NoError(t, err)
			assert.Equal(t, 2*len("quic"), n)

			used, unused := familySenders(remote.IP, v4, v6)
			assert.Empty(t, unused.Packets())
			sent := used.Packets()
			require.Len(t, sent, 2)
			for _, p := range sent {
				assert.Equal(t, netip.MustParseAddr(addrs[0]), p.Src)
				assert.Equal(t, netip.MustParseAddr(addrs[1]), p.Dst)
				assert.Equal(t, uint8(17), p.Proto)
				assert.Equal(t, uint8(11), p.HopLimit,
					"12 hops learned from 52 left of 64, plus hop-count-offset -1")
				assert.True(t, l4ChecksumValid(p))
			}
		})
	}
}

// TestDesync_SkipsFakesToLinkScoped checks that no fake packets go to a
// link-local or multicast destination of either family, though no hop
// count is learned for it, and that the skip logs at debug level only.
func TestDesync_SkipsFakesToLinkScoped(t *testing.T) {
	tcs := []struct {
		name, local, remote string
		wantFakes           bool
	}{
		{"ipv6 link-local", "fe80::11", "fe80::1", false},
		{"ipv6 multicast", "2001:db8::11", "ff02::fb", false},
		{"ipv4 link-local", "169.254.1.11", "169.254.1.1", false},
		{"ipv4 multicast", "192.168.1.11", "224.0.0.251", false},
		{"ipv6 global", "2001:db8::11", "2001:db8:1::1", true},
		{"ipv4 global", "192.168.1.11", "203.0.113.1", true},
	}

	for _, tc := range tcs {
		t.Run("tls/"+tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			w := &recordingWriter{}
			d := NewTLSDesyncer(
				zerolog.New(&logs), w, stubHops{}, nil, NewStaticGate(nil, nil),
			)
			opts := tlsOpts(1, 100)
			opts.SynAckTimeout = 0
			conn := &stubConn{
				local:  &net.TCPAddr{IP: net.ParseIP(tc.local), Port: 50000},
				remote: &net.TCPAddr{IP: net.ParseIP(tc.remote), Port: 443},
			}

			n, err := d.Desync(context.Background(), conn, fakeMsg(), opts, baseConnOpts())
			require.NoError(t, err)
			assert.Equal(t, len(config.FakeClientHello), n, "the real Client Hello is sent")
			assert.Equal(t, tc.wantFakes, len(w.packets) > 0)
			assert.NotContains(t, logs.String(), `"level":"warn"`)
		})

		t.Run("udp/"+tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			w := &udpWriter{}
			d := NewUDPDesyncer(zerolog.New(&logs), w, stubHops{}, NewStaticGate(nil, nil))
			conn := udpConn{
				local:  &net.UDPAddr{IP: net.ParseIP(tc.local), Port: 50000},
				remote: &net.UDPAddr{IP: net.ParseIP(tc.remote), Port: 443},
			}

			_, err := d.Desync(
				context.Background(),
				conn,
				&config.UDPOptions{FakePreflight: 2, FakePacket: make([]byte, 8)},
				baseConnOpts(),
			)
			require.NoError(t, err)
			assert.Equal(t, tc.wantFakes, w.n > 0)
			assert.NotContains(t, logs.String(), `"level":"warn"`)
		})
	}
}
