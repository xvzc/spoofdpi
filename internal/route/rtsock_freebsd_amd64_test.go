package route

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/netutil"
	xroute "golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// TestTableRoutes_FreeBSDKernelForm reads dump entries in the FreeBSD
// amd64 kernel form: a 152-byte rt_msghdr, addresses rounded up to 8
// bytes, and compact netmasks.
func TestTableRoutes_FreeBSDKernelForm(t *testing.T) {
	addrs := unix.RTA_DST | unix.RTA_GATEWAY | unix.RTA_NETMASK | unix.RTA_IFP

	// A tagged FIB default via gateway, as spoofdpi adds it.
	defFlags := unix.RTF_UP | unix.RTF_GATEWAY | unix.RTF_STATIC | unix.RTF_PROTO2
	def := rtmKernelMessage(0x98, defFlags, 1, addrs, []byte{
		// RTAX_DST: 0.0.0.0
		0x10, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		// RTAX_GATEWAY: 192.168.1.1
		0x10, 0x02, 0, 0, 192, 168, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0,
		// RTAX_NETMASK: zero-length sockaddr in 8 bytes
		0, 0, 0, 0, 0, 0, 0, 0,
		// RTAX_IFP: sockaddr_dl "em0" with a MAC, 17 bytes, padded to 24
		0x11, 0x12, 1, 0, 0x06, 3, 6, 0, 'e', 'm', '0',
		0x02, 0, 0, 0, 0, 0x01, 0, 0, 0, 0, 0, 0, 0,
	})
	// A tagged FIB subnet route via the interface, as
	// `route add -net 192.168.1.0/24 -iface em0` adds it.
	netFlags := unix.RTF_UP | unix.RTF_STATIC | unix.RTF_PROTO2
	subnet := rtmKernelMessage(0x98, netFlags, 1, addrs, []byte{
		// RTAX_DST: 192.168.1.0
		0x10, 0x02, 0, 0, 192, 168, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		// RTAX_GATEWAY: sockaddr_dl_short of index 1, 12 bytes, padded to 16
		0x0c, 0x12, 1, 0, 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		// RTAX_NETMASK: 255.255.255.0 in 7 bytes, padded to 8
		0x07, 0x00, 0, 0, 0xff, 0xff, 0xff, 0,
		// RTAX_IFP: sockaddr_dl "em0" with a MAC, 17 bytes, padded to 24
		0x11, 0x12, 1, 0, 0x06, 3, 6, 0, 'e', 'm', '0',
		0x02, 0, 0, 0, 0, 0x01, 0, 0, 0, 0, 0, 0, 0,
	})

	msgs, err := xroute.ParseRIB(xroute.RIBTypeRoute, append(def, subnet...))
	require.NoError(t, err)
	assert.Equal(t, []TableRoute{
		{
			Dst:     netip.MustParsePrefix("0.0.0.0/0"),
			Gateway: netip.MustParseAddr("192.168.1.1"),
			Index:   1,
			IfName:  "em0",
			Flags:   defFlags,
		},
		{
			Dst:         netip.MustParsePrefix("192.168.1.0/24"),
			GatewayLink: 1,
			Index:       1,
			IfName:      "em0",
			Flags:       netFlags,
		},
	}, tableRoutes(msgs, netutil.FamilyV4, nil))
}
