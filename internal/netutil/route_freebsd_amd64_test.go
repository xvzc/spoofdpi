package netutil

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

// TestKernelRouteFromReply_FreeBSDKernelForm parses a hand-written RTM_GET
// reply in the FreeBSD amd64 kernel form: a 152-byte rt_msghdr and
// addresses rounded up to 8 bytes, with a zero-length netmask.
func TestKernelRouteFromReply_FreeBSDKernelForm(t *testing.T) {
	body := []byte{
		// RTAX_DST: 0.0.0.0
		0x10, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		// RTAX_GATEWAY: 192.168.1.1
		0x10, 0x02, 0, 0, 192, 168, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0,
		// RTAX_NETMASK: zero-length sockaddr in 8 bytes
		0, 0, 0, 0, 0, 0, 0, 0,
		// RTAX_IFP: sockaddr_dl "em0" with a MAC, 17 bytes, padded to 24
		0x11, 0x12, 1, 0, 0x06, 3, 6, 0, 'e', 'm', '0',
		0x02, 0, 0, 0, 0, 0x01, 0, 0, 0, 0, 0, 0, 0,
		// RTAX_IFA: 192.168.1.11
		0x10, 0x02, 0, 0, 192, 168, 1, 11, 0, 0, 0, 0, 0, 0, 0, 0,
	}
	addrs := unix.RTA_DST | unix.RTA_GATEWAY | unix.RTA_NETMASK |
		unix.RTA_IFP | unix.RTA_IFA
	b := rtmKernelMessage(0x98, unix.RTF_UP|unix.RTF_GATEWAY, 1, addrs, body)

	assert.Equal(t, kernelRoute{
		ifIndex: 1,
		gateway: netip.MustParseAddr("192.168.1.1"),
		src:     netip.MustParseAddr("192.168.1.11"),
	}, kernelRouteFromBytes(t, b, "192.0.2.1"))
}
