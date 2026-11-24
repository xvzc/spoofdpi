//go:build network && darwin

package tun

import (
	"fmt"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/capture"
	"github.com/xvzc/spoofdpi/internal/inject"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/testutil"
)

// testNet1 is a TEST-NET-1 address (RFC 5737) that no host answers.
var testNet1 = netip.MustParseAddr("192.0.2.1")

// TestEgressControlLive_RawSocket_RequireRoot pins the raw IPv4 socket of fake packets
// with EgressControl, as TUN mode does, and checks that the pin holds:
//   - the socket's IP_BOUND_IF, read back, is the pinned interface;
//   - pinned to the interface of the default route, a TTL 1 packet to
//     TEST-NET-1 leaves on that interface.
//
// Run it while spoofdpi's TUN mode is up to check that pinned fakes escape
// the TUN's 0/1 and 128/1 routes.
//
// It does not pin to lo0 to see a send fail: darwin ignores IP_BOUND_IF
// set to the loopback interface, and the packet leaves by the default
// route.
func TestEgressControlLive_RawSocket_RequireRoot(t *testing.T) {
	testutil.RequireRoot(t)
	route, err := netutil.DiscoverRoute(nil)
	if err != nil {
		t.Skipf("no IPv4 default route: %v", err)
	}
	src, ok := netip.AddrFromSlice(route.LocalIP)
	require.True(t, ok)
	src = src.Unmap()

	t.Run("default interface", func(t *testing.T) {
		h, err := capture.NewHandleWithReadTimeout(&route.Iface, 100*time.Millisecond)
		require.NoError(t, err)
		t.Cleanup(h.Close)
		dh, ok := h.(*capture.DefaultHandle)
		require.True(t, ok)
		require.NoError(t, dh.SetBPFFilter(fmt.Sprintf(
			"tcp and src port 47002 and dst host %s and dst port 9", testNet1,
		)))

		s := openPinned(t, route)
		require.NoError(t, s.Send(tcpPacket(t, src, testNet1, 47002)))

		seen := false
		for deadline := time.Now().Add(3 * time.Second); !seen && time.Now().Before(deadline); {
			data, _, err := h.ReadPacketData()
			if capture.IsReadTimeout(err) {
				continue
			}
			require.NoError(t, err)
			pkt := gopacket.NewPacket(data, h.LinkType(), gopacket.Default)
			ip4, ok := pkt.NetworkLayer().(*layers.IPv4)
			seen = ok && ip4.TTL == 1
		}
		assert.True(t, seen, "the pinned fake leaves on %s", route.Iface.Name)
	})
}

// openPinned opens the IPv4 sender of fake packets pinned to route's
// interface, and checks that the raw socket's IP_BOUND_IF is that
// interface.
func openPinned(t *testing.T, route *netutil.Route) inject.Sender {
	t.Helper()
	control := EgressControl(route, 0)
	require.NotNil(t, control)

	boundIndex := -1
	readBack := func(network, address string, c syscall.RawConn) error {
		if err := control(network, address, c); err != nil {
			return err
		}
		var sockErr error
		err := c.Control(func(fd uintptr) {
			boundIndex, sockErr = syscall.GetsockoptInt(
				int(fd), syscall.IPPROTO_IP, syscall.IP_BOUND_IF,
			)
		})
		if err != nil {
			return err
		}
		return sockErr
	}

	s, err := inject.Open(netutil.FamilyV4, inject.Options{Control: readBack})
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	assert.Equal(t, route.Iface.Index, boundIndex, "IP_BOUND_IF of the raw socket")
	return s
}

// tcpPacket returns a TTL 1 ACK segment from src:srcPort to dst:9.
func tcpPacket(t *testing.T, src, dst netip.Addr, srcPort uint16) inject.Packet {
	t.Helper()
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: 9,
		Seq:     0x5eed0001,
		Ack:     0x5eed0002,
		ACK:     true,
		Window:  12345,
	}
	require.NoError(t, tcp.SetNetworkLayerForChecksum(&layers.IPv4{
		SrcIP:    src.AsSlice(),
		DstIP:    dst.AsSlice(),
		Protocol: layers.IPProtocolTCP,
	}))
	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, tcp))
	return inject.Packet{Src: src, Dst: dst, Proto: 6, HopLimit: 1, L4: buf.Bytes()}
}
