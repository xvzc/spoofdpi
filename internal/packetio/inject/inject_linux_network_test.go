//go:build network && linux

package inject

import (
	"fmt"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/packetio/capture"
	"github.com/xvzc/spoofdpi/internal/testutil"
)

// TestSenderLive_BoundToDevice_RequireRoot sends one IPv4 fake into a real
// loopback connection from a socket bound to lo with SO_BINDTODEVICE, as
// TUN mode binds it to the physical interface, and checks that the fake
// leaves on lo with its source, routed with IP_PKTINFO.
func TestSenderLive_BoundToDevice_RequireRoot(t *testing.T) {
	testutil.RequireRoot(t)
	client, _ := loopbackConn(t, "tcp4", "127.0.0.1:0")
	src := unmapped(client.LocalAddr())
	dst := unmapped(client.RemoteAddr())

	lo := loopbackInterface(t)
	h, linkType := openLiveCapture(t, lo, "")
	bindToLo := func(_, _ string, c syscall.RawConn) error {
		var sockErr error
		err := c.Control(func(fd uintptr) {
			sockErr = syscall.SetsockoptString(
				int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, lo.Name,
			)
		})
		if err != nil {
			return err
		}
		if sockErr != nil {
			return fmt.Errorf("set SO_BINDTODEVICE: %w", sockErr)
		}
		return nil
	}
	s, err := Open(netutil.FamilyV4, Options{Control: bindToLo})
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	require.NoError(t, s.Send(fakePacket(t, src, dst)))
	assertFake(t, captureFake(t, h, linkType), src, dst)
}

// openLiveCapture opens a capture on iface and returns it with the link
// type its packets are decoded as. The AF_PACKET handle takes no pcap
// filter expressions, so it passes every packet and filter is not used:
// captureFake picks the fake out by its sequence number.
func openLiveCapture(
	t *testing.T,
	iface *net.Interface,
	_ string,
) (capture.Handle, layers.LinkType) {
	t.Helper()
	h, err := capture.NewHandleWithReadTimeout(iface, 100*time.Millisecond)
	require.NoError(t, err)
	t.Cleanup(h.Close)
	return h, h.LinkType()
}
