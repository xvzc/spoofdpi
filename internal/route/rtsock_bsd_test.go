//go:build darwin || freebsd

package route

import (
	"errors"
	"net/netip"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/netutil"
	xroute "golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// indexOnlyLink returns the sockaddr_dl of a link gateway with its index
// alone, for tests that do not look up interfaces.
func indexOnlyLink(index int) (*xroute.LinkAddr, error) {
	return &xroute.LinkAddr{Index: index}, nil
}

// parsedRouteMessage marshals the routing message of type typ for r, with
// link gateways from link, and parses it back, as the kernel reads it.
func parsedRouteMessage(
	t *testing.T,
	typ int,
	r TableRoute,
	link func(int) (*xroute.LinkAddr, error),
) *xroute.RouteMessage {
	t.Helper()
	m, err := routeMessage(typ, r, link)
	require.NoError(t, err)
	b, err := marshalRouteMessage(m)
	require.NoError(t, err)
	msgs, err := xroute.ParseRIB(xroute.RIBTypeRoute, b)
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	return msgs[0].(*xroute.RouteMessage)
}

func TestRouteMessage(t *testing.T) {
	upStatic := unix.RTF_UP | unix.RTF_STATIC

	tcs := []struct {
		name      string
		typ       int
		r         TableRoute
		wantFlags int
		wantIndex int
		wantAddrs []xroute.Addr
	}{
		{
			name: "tagged ipv4 host route via interface",
			typ:  unix.RTM_ADD,
			r: TableRoute{
				Dst:         netip.MustParsePrefix("192.0.2.123/32"),
				GatewayLink: 1,
				Flags:       unix.RTF_PROTO2,
			},
			wantFlags: upStatic | unix.RTF_HOST | unix.RTF_PROTO2,
			wantAddrs: rtmAddrs(
				inet4("192.0.2.123"), &xroute.LinkAddr{Index: 1}, nil, nil, nil,
			)[:unix.RTAX_NETMASK+1],
		},
		{
			name: "ipv4 network route via gateway",
			typ:  unix.RTM_ADD,
			r: TableRoute{
				Dst:     netip.MustParsePrefix("192.0.2.0/24"),
				Gateway: netip.MustParseAddr("192.168.1.1"),
			},
			wantFlags: upStatic | unix.RTF_GATEWAY,
			wantAddrs: rtmAddrs(
				inet4("192.0.2.0"), inet4("192.168.1.1"), inet4("255.255.255.0"),
				nil, nil,
			)[:unix.RTAX_NETMASK+1],
		},
		{
			name: "default route via gateway with an index",
			typ:  unix.RTM_ADD,
			r: TableRoute{
				Dst:     netip.MustParsePrefix("0.0.0.0/0"),
				Gateway: netip.MustParseAddr("172.20.0.1"),
				Index:   4,
				Flags:   unix.RTF_PROTO2,
			},
			wantFlags: upStatic | unix.RTF_GATEWAY | unix.RTF_PROTO2,
			wantIndex: 4,
			wantAddrs: rtmAddrs(
				inet4("0.0.0.0"), inet4("172.20.0.1"), inet4("0.0.0.0"), nil, nil,
			)[:unix.RTAX_NETMASK+1],
		},
		{
			name: "default route via ipv4 link-local gateway",
			typ:  unix.RTM_ADD,
			r: TableRoute{
				Dst:     netip.MustParsePrefix("0.0.0.0/0"),
				Gateway: netip.MustParseAddr("169.254.1.1"),
			},
			wantFlags: upStatic | unix.RTF_GATEWAY,
			wantAddrs: rtmAddrs(
				inet4("0.0.0.0"), inet4("169.254.1.1"), inet4("0.0.0.0"), nil, nil,
			)[:unix.RTAX_NETMASK+1],
		},
		{
			name: "ipv6 network route via interface, destination masked",
			typ:  unix.RTM_ADD,
			r: TableRoute{
				Dst:         netip.MustParsePrefix("2001:db8::1/3"),
				GatewayLink: 20,
			},
			wantFlags: upStatic,
			wantAddrs: rtmAddrs(
				inet6("2000::"), &xroute.LinkAddr{Index: 20}, inet6("e000::"), nil, nil,
			)[:unix.RTAX_NETMASK+1],
		},
		{
			name: "ipv4 delete without gateway",
			typ:  unix.RTM_DELETE,
			r: TableRoute{
				Dst:   netip.MustParsePrefix("0.0.0.0/0"),
				Flags: unix.RTF_PROTO2,
			},
			wantFlags: upStatic | unix.RTF_PROTO2,
			wantAddrs: rtmAddrs(
				inet4("0.0.0.0"), nil, inet4("0.0.0.0"), nil, nil,
			)[:unix.RTAX_NETMASK+1],
		},
		{
			name: "ipv6 host route via interface",
			typ:  unix.RTM_ADD,
			r: TableRoute{
				Dst:         netip.MustParsePrefix("2001:db8::123/128"),
				GatewayLink: 1,
			},
			wantFlags: upStatic | unix.RTF_HOST,
			wantAddrs: rtmAddrs(
				inet6("2001:db8::123"), &xroute.LinkAddr{Index: 1}, nil, nil, nil,
			)[:unix.RTAX_NETMASK+1],
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			m := parsedRouteMessage(t, tc.typ, tc.r, indexOnlyLink)
			assert.Equal(t, unix.RTM_VERSION, m.Version)
			assert.Equal(t, tc.typ, m.Type)
			assert.Equal(t, tc.wantFlags, m.Flags)
			assert.Equal(t, tc.wantIndex, m.Index)
			assert.Positive(t, m.Seq)
			// ParseRIB returns RTAX_MAX addresses.
			want := make([]xroute.Addr, len(m.Addrs))
			copy(want, tc.wantAddrs)
			assert.Equal(t, want, m.Addrs)
		})
	}
}

func TestRouteMessage_Errors(t *testing.T) {
	dst := netip.MustParsePrefix("192.0.2.0/24")
	tcs := []struct {
		name string
		r    TableRoute
		want string
	}{
		{
			name: "no destination",
			r:    TableRoute{GatewayLink: 1},
			want: "invalid destination",
		},
		{
			name: "gateway of another family",
			r:    TableRoute{Dst: dst, Gateway: netip.MustParseAddr("2001:db8::1")},
			want: "another address family",
		},
		{
			name: "link-local gateway",
			r: TableRoute{
				Dst:     netip.MustParsePrefix("::/0"),
				Gateway: netip.MustParseAddr("fe80::1"),
			},
			want: "link-local",
		},
		{
			name: "zoned gateway",
			r: TableRoute{
				Dst:     netip.MustParsePrefix("::/0"),
				Gateway: netip.MustParseAddr("2001:db8::1%en0"),
			},
			want: "link-local",
		},
		{
			name: "ip and link gateway",
			r: TableRoute{
				Dst:         dst,
				Gateway:     netip.MustParseAddr("192.0.2.1"),
				GatewayLink: 1,
			},
			want: "both",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			_, err := routeMessage(unix.RTM_ADD, tc.r, indexOnlyLink)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}

	t.Run("link gateway lookup fails", func(t *testing.T) {
		noLink := func(int) (*xroute.LinkAddr, error) {
			return nil, errors.New("no such network interface")
		}
		_, err := routeMessage(unix.RTM_ADD, TableRoute{Dst: dst, GatewayLink: 9}, noLink)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "gateway link#9: no such network interface")
	})
}

// TestRouteMessage_KernelFlags checks that a write keeps only the flags a
// caller may set, so a dumped route passed back loses the kernel's bits,
// such as RTF_LLINFO and RTF_DONE, and its own RTF_HOST or RTF_GATEWAY.
func TestRouteMessage_KernelFlags(t *testing.T) {
	r := TableRoute{
		Dst:         netip.MustParsePrefix("192.0.2.0/24"),
		GatewayLink: 1,
		Flags:       0x7fffffff,
	}
	for _, typ := range []int{unix.RTM_ADD, unix.RTM_DELETE} {
		m := parsedRouteMessage(t, typ, r, indexOnlyLink)
		assert.Equal(t, unix.RTF_UP|unix.RTF_STATIC|callerRouteFlags, m.Flags)
		assert.Zero(t, m.Flags&(unix.RTF_LLINFO|unix.RTF_DONE|unix.RTF_HOST|
			unix.RTF_GATEWAY))
	}
}

// TestAddRoute_NoGateway checks that AddRoute refuses a route without
// gateway before it opens a routing socket.
func TestAddRoute_NoGateway(t *testing.T) {
	err := AddRoute(0, TableRoute{Dst: netip.MustParsePrefix("192.0.2.0/24")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no gateway")
}

func TestTableRoutes(t *testing.T) {
	lo0 := &xroute.LinkAddr{Index: 1, Name: "lo0"}
	en0 := &xroute.LinkAddr{Index: 4, Name: "en0"}
	tagged := unix.RTF_UP | unix.RTF_STATIC | unix.RTF_PROTO2
	upGw := unix.RTF_UP | unix.RTF_GATEWAY

	dump := func(flags, index int, dst, gw, mask, ifp xroute.Addr) *xroute.RouteMessage {
		m := rtmReply(flags, index, rtmAddrs(dst, gw, mask, ifp, nil)...)
		m.Seq = 0
		return m
	}
	// The names of the host's interfaces, for the routes the kernel
	// reports without one; en0 is not among them.
	names := map[int]string{1: "lo-host", 20: "utun4"}
	msgs := parseRTMFixture(t,
		// Tagged host route via an interface.
		dump(tagged|unix.RTF_HOST, 1,
			inet4("192.0.2.123"), &xroute.LinkAddr{Index: 1}, nil, lo0),
		// Default route via gateway, without interface name and of an
		// interface that is gone.
		dump(upGw|unix.RTF_STATIC, 4,
			inet4("0.0.0.0"), inet4("192.168.1.1"), inet4("0.0.0.0"), nil),
		// Network route.
		dump(unix.RTF_UP, 4,
			inet4("192.168.1.0"), &xroute.LinkAddr{Index: 4}, inet4("255.255.255.0"), en0),
		// Left out: a netmask that is not a prefix.
		dump(unix.RTF_UP, 4,
			inet4("10.0.0.0"), &xroute.LinkAddr{Index: 4}, inet4("255.0.255.0"), en0),
		// Left out: no destination.
		dump(unix.RTF_UP, 4, nil, inet4("192.168.1.1"), nil, en0),
		// IPv6 tagged route.
		dump(tagged, 20,
			inet6("2000::"), &xroute.LinkAddr{Index: 20}, inet6("e000::"), nil),
	)

	assert.Equal(t, []TableRoute{
		{
			Dst:         netip.MustParsePrefix("192.0.2.123/32"),
			GatewayLink: 1,
			Index:       1,
			IfName:      "lo0",
			Flags:       tagged | unix.RTF_HOST,
		},
		{
			Dst:     netip.MustParsePrefix("0.0.0.0/0"),
			Gateway: netip.MustParseAddr("192.168.1.1"),
			Index:   4,
			Flags:   upGw | unix.RTF_STATIC,
		},
		{
			Dst:         netip.MustParsePrefix("192.168.1.0/24"),
			GatewayLink: 4,
			Index:       4,
			IfName:      "en0",
			Flags:       unix.RTF_UP,
		},
	}, tableRoutes(msgs, netutil.FamilyV4, names))

	assert.Equal(t, []TableRoute{
		{
			Dst:         netip.MustParsePrefix("2000::/3"),
			GatewayLink: 20,
			Index:       20,
			IfName:      "utun4",
			Flags:       tagged,
		},
	}, tableRoutes(msgs, netutil.FamilyV6, names))
}

func TestTableRouteString(t *testing.T) {
	r := TableRoute{
		Dst:     netip.MustParsePrefix("0.0.0.0/0"),
		Gateway: netip.MustParseAddr("192.168.1.1"),
		Index:   4,
		IfName:  "en0",
		Flags:   0x40803,
	}
	assert.Equal(
		t,
		"0.0.0.0/0 gateway 192.168.1.1 index 4 (en0) flags 0x40803",
		r.String(),
	)

	r = TableRoute{Dst: netip.MustParsePrefix("2000::/3"), GatewayLink: 20}
	assert.Equal(t, "2000::/3 gateway link#20 flags 0x0", r.String())
}

// TestDumpRoutes_Loopback reads the real routing table, which needs no
// privileges, and finds the host route to 127.0.0.1 on the loopback
// interface.
func TestDumpRoutes_Loopback(t *testing.T) {
	routes, err := DumpRoutes(netutil.FamilyV4, 0)
	require.NoError(t, err)
	i := slices.IndexFunc(routes, func(r TableRoute) bool {
		return r.Dst == netip.MustParsePrefix("127.0.0.1/32")
	})
	require.GreaterOrEqual(t, i, 0, "routes: %v", routes)
	lo := routes[i]
	assert.Equal(t, "lo0", lo.IfName)
	assert.Positive(t, lo.Index)
	assert.NotZero(t, lo.Flags&unix.RTF_HOST)

	routes, err = DumpRoutes(netutil.FamilyV6, 0)
	require.NoError(t, err)
	for _, r := range routes {
		assert.True(t, r.Dst.Addr().Is6(), "route %s", r)
	}
}
