package route

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/netutil"
	xroute "golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// TestRouteMessage_Scoped builds the message of
// `route add -ifscope en0 default 172.20.0.1`, tagged: RTF_IFSCOPE with
// the scope in rtm_index.
func TestRouteMessage_Scoped(t *testing.T) {
	m := parsedRouteMessage(t, unix.RTM_ADD, TableRoute{
		Dst:     netip.MustParsePrefix("0.0.0.0/0"),
		Gateway: netip.MustParseAddr("172.20.0.1"),
		Index:   11,
		Flags:   unix.RTF_IFSCOPE | unix.RTF_PROTO2,
	}, indexOnlyLink)
	assert.Equal(t, unix.RTF_UP|unix.RTF_STATIC|unix.RTF_GATEWAY|
		unix.RTF_IFSCOPE|unix.RTF_PROTO2, m.Flags)
	assert.Equal(t, 11, m.Index)
	assert.Equal(t, inet4("172.20.0.1"), m.Addrs[unix.RTAX_GATEWAY])
	assert.Equal(t, inet4("0.0.0.0"), m.Addrs[unix.RTAX_NETMASK])
}

// TestTableRoutes_DarwinKernelForm reads dump entries in the darwin kernel
// form: a 92-byte rt_msghdr, addresses rounded up to 4 bytes, and compact
// netmasks.
func TestTableRoutes_DarwinKernelForm(t *testing.T) {
	// darwin dumps carry no RTAX_IFP; the names come from the interfaces.
	addrs := unix.RTA_DST | unix.RTA_GATEWAY | unix.RTA_NETMASK
	names := map[int]string{11: "en0", 21: "utun6"}

	// The scoped default that spoofdpi adds, as `netstat -rn` shows it:
	// default 172.20.0.1 UGScIg en0 with the tag.
	scopedFlags := unix.RTF_UP | unix.RTF_GATEWAY | unix.RTF_STATIC |
		unix.RTF_PRCLONING | unix.RTF_IFSCOPE | unix.RTF_PROTO2
	scoped := rtmKernelMessage(0x5c, scopedFlags, 11, addrs, []byte{
		// RTAX_DST: 0.0.0.0
		0x10, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		// RTAX_GATEWAY: 172.20.0.1
		0x10, 0x02, 0, 0, 172, 20, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
		// RTAX_NETMASK: zero-length sockaddr in 4 bytes
		0, 0, 0, 0,
	})
	// A cloned host route that the kernel marked with PROTO3, which darwin
	// reserves (it drops PROTO3 from RTM_ADD):
	// 172.20.0.1 link#21 UHW3I utun6.
	clonedFlags := unix.RTF_UP | unix.RTF_HOST | unix.RTF_WASCLONED |
		unix.RTF_PROTO3 | unix.RTF_IFSCOPE
	cloned := rtmKernelMessage(0x5c, clonedFlags, 21, addrs&^unix.RTA_NETMASK, []byte{
		// RTAX_DST: 172.20.0.1
		0x10, 0x02, 0, 0, 172, 20, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
		// RTAX_GATEWAY: sockaddr_dl of index 21, 20 bytes
		0x14, 0x12, 21, 0, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	})

	msgs, err := xroute.ParseRIB(xroute.RIBTypeRoute, append(scoped, cloned...))
	require.NoError(t, err)
	assert.Equal(t, []TableRoute{
		{
			Dst:     netip.MustParsePrefix("0.0.0.0/0"),
			Gateway: netip.MustParseAddr("172.20.0.1"),
			Index:   11,
			IfName:  "en0",
			Flags:   scopedFlags,
		},
		{
			Dst:         netip.MustParsePrefix("172.20.0.1/32"),
			GatewayLink: 21,
			Index:       21,
			IfName:      "utun6",
			Flags:       clonedFlags,
		},
	}, tableRoutes(msgs, netutil.FamilyV4, names))
}

func TestRoutes_DarwinHasNoFIBs(t *testing.T) {
	_, err := DumpRoutes(netutil.FamilyV4, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no FIBs")

	err = DeleteRoute(1, TableRoute{Dst: netip.MustParsePrefix("192.0.2.123/32")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no FIBs")
}

// TestRouteMessage_DarwinLinkGateway checks that a link gateway goes out
// as a sockaddr_dl of at least sizeof(struct sockaddr_dl), with the
// interface's name and address, as route(8) sends it for -interface.
func TestRouteMessage_DarwinLinkGateway(t *testing.T) {
	en0 := &net.Interface{
		Index:        4,
		Name:         "en0",
		HardwareAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 0x01},
	}
	lo0 := &net.Interface{Index: 1, Name: "lo0"}
	long := &net.Interface{
		Index:        30,
		Name:         "bridge100",
		HardwareAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 0x02},
	}

	tcs := []struct {
		name    string
		iface   *net.Interface
		wantLen int
	}{
		{name: "ethernet", iface: en0, wantLen: unix.SizeofSockaddrDatalink},
		{name: "no hardware address", iface: lo0, wantLen: unix.SizeofSockaddrDatalink},
		{name: "longer than the struct", iface: long, wantLen: 8 + 9 + 6},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			link := func(index int) (*xroute.LinkAddr, error) {
				assert.Equal(t, tc.iface.Index, index)
				return linkGatewayOf(tc.iface), nil
			}
			m, err := routeMessage(unix.RTM_ADD, TableRoute{
				Dst:         netip.MustParsePrefix("192.0.2.123/32"),
				GatewayLink: tc.iface.Index,
			}, link)
			require.NoError(t, err)
			b, err := marshalRouteMessage(m)
			require.NoError(t, err)

			// The gateway follows the rt_msghdr and the 16-byte destination.
			gw := b[unix.SizeofRtMsghdr+unix.SizeofSockaddrInet4:]
			assert.Equal(t, tc.wantLen, int(gw[0]), "sdl_len")
			assert.Equal(t, len(b), int(binary.NativeEndian.Uint16(b[0:2])), "msglen")
			assert.Zero(t, len(b)%4)

			msgs, err := xroute.ParseRIB(xroute.RIBTypeRoute, b)
			require.NoError(t, err)
			require.Len(t, msgs, 1)
			got := msgs[0].(*xroute.RouteMessage).Addrs[unix.RTAX_GATEWAY]
			want := &xroute.LinkAddr{Index: tc.iface.Index, Name: tc.iface.Name}
			if len(tc.iface.HardwareAddr) > 0 {
				want.Addr = tc.iface.HardwareAddr
			}
			assert.Equal(t, want, got)
		})
	}
}

// TestLinkGateway_Loopback looks up the real lo0.
func TestLinkGateway_Loopback(t *testing.T) {
	lo0, err := net.InterfaceByName("lo0")
	require.NoError(t, err)
	gw, err := linkGateway(lo0.Index)
	require.NoError(t, err)
	assert.Equal(t, &xroute.LinkAddr{Index: lo0.Index, Name: "lo0"}, gw)
}

// TestRouteMessage_DarwinDeleteWithoutGateway checks that a delete leaves
// the gateway out, as darwin does not check it, so even a link-local one
// is accepted, and that the scope stays.
func TestRouteMessage_DarwinDeleteWithoutGateway(t *testing.T) {
	tcs := []struct {
		name string
		r    TableRoute
	}{
		{
			name: "scoped default via gateway",
			r: TableRoute{
				Dst:     netip.MustParsePrefix("0.0.0.0/0"),
				Gateway: netip.MustParseAddr("172.20.0.1"),
				Index:   11,
				Flags:   unix.RTF_IFSCOPE | unix.RTF_PROTO2,
			},
		},
		{
			name: "link-local gateway",
			r: TableRoute{
				Dst:     netip.MustParsePrefix("::/0"),
				Gateway: netip.MustParseAddr("fe80::1%en0"),
				Index:   11,
				Flags:   unix.RTF_IFSCOPE | unix.RTF_PROTO2,
			},
		},
		{
			name: "link gateway",
			r: TableRoute{
				Dst:         netip.MustParsePrefix("2000::/3"),
				GatewayLink: 21,
				Flags:       unix.RTF_PROTO2,
			},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			noLookup := func(int) (*xroute.LinkAddr, error) {
				t.Error("a delete looks up no link gateway")
				return nil, nil
			}
			m := parsedRouteMessage(t, unix.RTM_DELETE, tc.r, noLookup)
			assert.Nil(t, m.Addrs[unix.RTAX_GATEWAY])
			assert.Zero(t, m.Flags&unix.RTF_GATEWAY)
			assert.Equal(t, tc.r.Flags, m.Flags&tc.r.Flags)
			assert.Equal(t, tc.r.Index, m.Index)
		})
	}
}
