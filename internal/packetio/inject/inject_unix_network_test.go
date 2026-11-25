//go:build network && (darwin || freebsd || linux)

package inject

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/packetio/capture"
	"github.com/xvzc/spoofdpi/internal/route"
	"github.com/xvzc/spoofdpi/internal/testutil"
)

// liveFakeSeq and liveFakeAck are the sequence numbers of the live tests'
// fake segments, far outside the window of the real connection.
const (
	liveFakeSeq = 0x5eed0001
	liveFakeAck = 0x5eed0002
)

// liveCaptureWait bounds the wait for a sent fake to show up in a capture.
const liveCaptureWait = 3 * time.Second

// TestSenderLive_LocalConnection_RequireRoot sends one fake TCP segment, with hop
// limit 1, a PSH|ACK, an MD5 signature option and out-of-window sequence
// numbers, into a real loopback connection, captures it on the loopback
// interface, and checks that the connection still carries data after it.
//
// The IPv4 header checksum is not checked here: darwin's lo0 offloads it
// (TXCSUM), so the kernel may leave it unset.
// TestSenderLive_RoutedInterface_RequireRoot checks it on the interface of a
// route out of the host.
func TestSenderLive_LocalConnection_RequireRoot(t *testing.T) {
	testutil.RequireRoot(t)

	tcs := []struct {
		fam     netutil.Family
		network string
		addr    string
	}{
		{fam: netutil.FamilyV4, network: "tcp4", addr: "127.0.0.1:0"},
		{fam: netutil.FamilyV6, network: "tcp6", addr: "[::1]:0"},
	}
	for _, tc := range tcs {
		t.Run(tc.fam.String(), func(t *testing.T) {
			client, server := loopbackConn(t, tc.network, tc.addr)
			src := unmapped(client.LocalAddr())
			dst := unmapped(client.RemoteAddr())

			lo := loopbackInterface(t)
			h, linkType := openLiveCapture(t, lo, fmt.Sprintf(
				"tcp and src port %d and dst port %d", src.Port(), dst.Port(),
			))

			s, err := Open(tc.fam, Options{})
			require.NoError(t, err)
			t.Cleanup(func() { _ = s.Close() })
			if v6, ok := s.(*v6Sender); ok {
				// x/net reads IPV6_CHECKSUM as unsigned, so the kernel's -1
				// (off) comes back as on with an offset of 0xffffffff.
				_, offset, err := v6.tcp.Checksum()
				require.NoError(t, err)
				assert.Equal(t, int32(-1), int32(offset),
					"the kernel must not rewrite the TCP checksum")
			}

			require.NoError(t, s.Send(fakePacket(t, src, dst)))
			got := captureFake(t, h, linkType)
			assertFake(t, got, src, dst)

			_, err = client.Write([]byte("real"))
			require.NoError(t, err)
			_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
			buf := make([]byte, 4)
			_, err = io.ReadFull(server, buf)
			require.NoError(t, err)
			assert.Equal(t, []byte("real"), buf, "the real connection survives the fake")
		})
	}
}

// TestSenderLive_RoutedInterface_RequireRoot sends one IPv4 fake TCP segment with
// TTL 1 to TEST-NET-1, where the first router drops it, and captures it
// on the interface the kernel routes it out of. That is a physical
// interface on most hosts, which, unlike darwin's lo0, may fill the IPv4
// header checksum in software: a checksum of 0 means it is offloaded,
// and is not checked. Linux always fills it.
func TestSenderLive_RoutedInterface_RequireRoot(t *testing.T) {
	testutil.RequireRoot(t)
	dstAddr := netip.MustParseAddr("192.0.2.1")
	path, err := route.RouteTo(dstAddr)
	if err != nil {
		t.Skipf("no route to %v: %v", dstAddr, err)
	}
	if !path.Src.IsValid() {
		t.Skipf("no source address for %v on %s", dstAddr, path.Iface.Name)
	}
	src := netip.AddrPortFrom(path.Src, 47000)
	dst := netip.AddrPortFrom(dstAddr, 9)

	h, linkType := openLiveCapture(t, &path.Iface, fmt.Sprintf(
		"tcp and dst host %s and dst port %d", dst.Addr(), dst.Port(),
	))
	s, err := Open(netutil.FamilyV4, Options{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	require.NoError(t, s.Send(fakePacket(t, src, dst)))
	got := captureFake(t, h, linkType)
	assertFake(t, got, src, dst)

	ip4, ok := got.NetworkLayer().(*layers.IPv4)
	require.True(t, ok)
	if ip4.Checksum == 0 {
		t.Logf("%s offloads the IPv4 header checksum; not checked", path.Iface.Name)
		return
	}
	assert.True(t, onesComplementValid(ip4.Contents), "valid IPv4 header checksum")
}

// loopbackInterface returns the loopback interface.
func loopbackInterface(t *testing.T) *net.Interface {
	t.Helper()
	ifaces, err := net.Interfaces()
	require.NoError(t, err)
	for i := range ifaces {
		if ifaces[i].Flags&net.FlagLoopback != 0 {
			return &ifaces[i]
		}
	}
	t.Skip("no loopback interface")
	return nil
}

// captureFake returns the first packet h captures whose TCP sequence
// number is liveFakeSeq, decoded as linkType.
func captureFake(
	t *testing.T,
	h capture.Handle,
	linkType layers.LinkType,
) gopacket.Packet {
	t.Helper()
	deadline := time.Now().Add(liveCaptureWait)
	for time.Now().Before(deadline) {
		data, _, err := h.ReadPacketData()
		if capture.IsReadTimeout(err) {
			continue
		}
		require.NoError(t, err)
		pkt := gopacket.NewPacket(data, linkType, gopacket.Default)
		if tcp, ok := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP); ok &&
			tcp.Seq == liveFakeSeq {
			return pkt
		}
	}
	t.Fatalf("the fake was not captured within %s", liveCaptureWait)
	return nil
}

// assertFake checks that pkt is the fake segment from src to dst: hop
// limit 1, the fake's sequence numbers, flags and MD5 option, and a valid
// TCP checksum. On IPv4 it also checks that the kernel filled the IP ID.
func assertFake(t *testing.T, pkt gopacket.Packet, src, dst netip.AddrPort) {
	t.Helper()
	var l4 []byte
	switch ip := pkt.NetworkLayer().(type) {
	case *layers.IPv4:
		assert.Equal(t, uint8(1), ip.TTL)
		assert.Equal(t, src.Addr().AsSlice(), []byte(ip.SrcIP.To4()))
		assert.Equal(t, dst.Addr().AsSlice(), []byte(ip.DstIP.To4()))
		assert.NotZero(t, ip.Id, "the kernel fills the IP ID")
		l4 = ip.Payload
	case *layers.IPv6:
		assert.Equal(t, uint8(1), ip.HopLimit)
		assert.Equal(t, src.Addr().AsSlice(), []byte(ip.SrcIP))
		assert.Equal(t, dst.Addr().AsSlice(), []byte(ip.DstIP))
		l4 = ip.Payload
	default:
		t.Fatalf("no IP layer in %v", pkt)
	}

	tcp, ok := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
	require.True(t, ok)
	assert.Equal(t, layers.TCPPort(src.Port()), tcp.SrcPort)
	assert.Equal(t, layers.TCPPort(dst.Port()), tcp.DstPort)
	assert.Equal(t, uint32(liveFakeSeq), tcp.Seq)
	assert.Equal(t, uint32(liveFakeAck), tcp.Ack)
	assert.True(t, tcp.PSH && tcp.ACK)
	require.Len(t, tcp.Options, 3)
	nop := layers.TCPOptionKind(layers.TCPOptionKindNop)
	assert.Equal(t, nop, tcp.Options[0].OptionType)
	assert.Equal(t, nop, tcp.Options[1].OptionType)
	assert.Equal(t, layers.TCPOptionKind(19), tcp.Options[2].OptionType)
	assert.Equal(t, uint8(18), tcp.Options[2].OptionLength)
	assert.Equal(t, []byte(liveFakePayload), tcp.Payload)
	assert.True(t, tcpChecksumValid(src.Addr(), dst.Addr(), l4), "valid TCP checksum")
}

// liveFakePayload is the payload of the live tests' fake segments.
const liveFakePayload = "spoofdpi live fake"

// fakePacket returns the fake segment from src to dst with hop limit 1.
func fakePacket(t *testing.T, src, dst netip.AddrPort) Packet {
	t.Helper()
	return Packet{
		Src:      src.Addr(),
		Dst:      dst.Addr(),
		Proto:    protoTCP,
		HopLimit: 1,
		L4:       fakeSegment(t, src, dst, []byte(liveFakePayload)),
	}
}

// tcpChecksumValid reports whether the checksum of l4, a TCP segment from
// src to dst, is valid over their pseudo-header.
func tcpChecksumValid(src, dst netip.Addr, l4 []byte) bool {
	pseudo := append(src.AsSlice(), dst.AsSlice()...)
	pseudo = append(pseudo, 0, protoTCP)
	pseudo = binary.BigEndian.AppendUint16(pseudo, uint16(len(l4)))
	return onesComplementValid(append(pseudo, l4...))
}

// onesComplementValid reports whether b, which carries its own Internet
// checksum, sums to 0xffff.
func onesComplementValid(b []byte) bool {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return sum == 0xffff
}

// loopbackConn returns both ends of a TCP connection on addr. It skips the
// test when the address cannot be listened on.
func loopbackConn(t *testing.T, network, addr string) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen(network, addr)
	if err != nil {
		t.Skipf("listen %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- c
	}()
	client, err = net.Dial(network, ln.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	server, ok := <-accepted
	require.True(t, ok, "accept failed")
	t.Cleanup(func() { _ = server.Close() })
	return client, server
}

// unmapped returns addr, a TCP address, with an IPv4 address unmapped.
func unmapped(addr net.Addr) netip.AddrPort {
	ap := addr.(*net.TCPAddr).AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// fakeSegment returns a PSH|ACK TCP segment from src to dst with an MD5
// signature option and payload, its checksum computed over src and dst.
func fakeSegment(t *testing.T, src, dst netip.AddrPort, payload []byte) []byte {
	t.Helper()
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(src.Port()),
		DstPort: layers.TCPPort(dst.Port()),
		Seq:     liveFakeSeq,
		Ack:     liveFakeAck,
		PSH:     true,
		ACK:     true,
		Window:  12345,
		Options: []layers.TCPOption{
			{OptionType: layers.TCPOptionKindNop},
			{OptionType: layers.TCPOptionKindNop},
			{OptionType: 19, OptionLength: 18, OptionData: make([]byte, 16)},
		},
	}
	var network gopacket.NetworkLayer
	if src.Addr().Is4() {
		network = &layers.IPv4{
			SrcIP:    src.Addr().AsSlice(),
			DstIP:    dst.Addr().AsSlice(),
			Protocol: layers.IPProtocolTCP,
		}
	} else {
		network = &layers.IPv6{
			SrcIP:      src.Addr().AsSlice(),
			DstIP:      dst.Addr().AsSlice(),
			NextHeader: layers.IPProtocolTCP,
		}
	}
	require.NoError(t, tcp.SetNetworkLayerForChecksum(network))
	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true},
		tcp, gopacket.Payload(payload)))
	return buf.Bytes()
}
