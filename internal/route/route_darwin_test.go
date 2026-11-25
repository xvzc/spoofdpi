package route

import (
	"encoding/hex"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/netutil"
	xroute "golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// darwinDefaultReply is a live RTM_GET reply for 192.0.2.1 on macOS 26
// (en0, IPv4), read unprivileged from a routing socket with the request
// rtmGet sends. The MAC, the addresses, the pid and the seq are replaced;
// the rest is as the kernel wrote it. The netmask of the default route is
// a zero-length sockaddr in 4 bytes, the sockaddr_dl of en0 is 20 bytes,
// and the gateway carries a stray byte in sin_zero.
const darwinDefaultReply = "" +
	"a40005040b000000430801403700000064000000070000000000000000000000" +
	"0000000000000000dc0500000000000000000000000000000000000000000000" +
	"0000000000000000000000000000000000000000000000000000000010020000" +
	"00000000000000000000000010020000c0a801010b0000000000000000000000" +
	"14120b0006030600656e3002000000000100000010020000c0a8010b00000000" +
	"00000000"

func TestKernelRouteFromReply_DarwinKernelForm(t *testing.T) {
	t.Run("captured default reply", func(t *testing.T) {
		b, err := hex.DecodeString(darwinDefaultReply)
		require.NoError(t, err)
		assert.Equal(t, kernelRoute{
			ifIndex: 11,
			gateway: netip.MustParseAddr("192.168.1.1"),
			src:     netip.MustParseAddr("192.168.1.11"),
		}, kernelRouteFromBytes(t, b, "192.0.2.1"))
	})

	t.Run("short netmask and trimmed sockaddr_dl", func(t *testing.T) {
		// A utun interface route to 10.0.0.0/8: the gateway is a bare
		// sockaddr_dl, the netmask is cut to the 5 bytes up to its last
		// non-zero byte, and the interface's sockaddr_dl carries the name
		// but no address.
		body := []byte{
			// RTAX_DST: 10.0.0.0
			0x10, 0x02, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			// RTAX_GATEWAY: sockaddr_dl of index 20, 8 bytes
			0x08, 0x12, 20, 0, 0, 0, 0, 0,
			// RTAX_NETMASK: 255.0.0.0 in 5 bytes, padded to 8
			0x05, 0x00, 0, 0, 0xff, 0, 0, 0,
			// RTAX_IFP: sockaddr_dl "utun4", 13 bytes, padded to 16
			0x0d, 0x12, 20, 0, 0xff, 5, 0, 0, 'u', 't', 'u', 'n', '4', 0, 0, 0,
			// RTAX_IFA: 10.8.0.2
			0x10, 0x02, 0, 0, 10, 8, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0,
		}
		addrs := unix.RTA_DST | unix.RTA_GATEWAY | unix.RTA_NETMASK |
			unix.RTA_IFP | unix.RTA_IFA
		b := rtmKernelMessage(0x5c, unix.RTF_UP|unix.RTF_STATIC, 20, addrs, body)
		assert.Equal(t, kernelRoute{
			ifIndex: 20,
			src:     netip.MustParseAddr("10.8.0.2"),
		}, kernelRouteFromBytes(t, b, "10.1.2.3"))
	})
}

// TestKernelRouteFromReply_Scoped checks that a scoped route, which the
// kernel chose for the lookup, is kept.
func TestKernelRouteFromReply_Scoped(t *testing.T) {
	m := rtmReply(unix.RTF_UP|unix.RTF_GATEWAY|unix.RTF_IFSCOPE, 4, rtmAddrs(
		inet4("0.0.0.0"), inet4("192.168.1.1"), inet4("0.0.0.0"),
		&xroute.LinkAddr{Index: 4, Name: "en0"}, nil,
	)...)
	reply := matchRTMReply(parseRTMFixture(t, m), 100, 7)
	require.NotNil(t, reply)

	got, err := kernelRouteFromReply(reply, netip.MustParseAddr("192.0.2.1"))
	require.NoError(t, err)
	assert.Equal(t, kernelRoute{
		ifIndex: 4,
		gateway: netip.MustParseAddr("192.168.1.1"),
	}, got)
}

// TestRouteTo_Loopback asks the real routing sockets of both families,
// which need no privileges, for the routes to 127.0.0.1 and ::1.
func TestRouteTo_Loopback(t *testing.T) {
	p, err := RouteTo(netip.MustParseAddr("127.0.0.1"))
	require.NoError(t, err)

	assert.Equal(t, netutil.FamilyV4, p.Family)
	assert.NotZero(t, p.Iface.Flags&net.FlagLoopback, "iface %s", p.Iface.Name)
	assert.False(t, p.Gateway.IsValid())
	assert.Equal(t, netip.MustParseAddr("127.0.0.1"), p.Src)

	p, err = RouteTo(netip.IPv6Loopback())
	require.NoError(t, err)
	assert.Equal(t, netutil.FamilyV6, p.Family)
	assert.NotZero(t, p.Iface.Flags&net.FlagLoopback, "iface %s", p.Iface.Name)
	assert.Equal(t, netip.IPv6Loopback(), p.Src)
}
