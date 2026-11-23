//go:build darwin || freebsd

package netutil

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// parseRTMFixture marshals msgs with x/net/route and parses them back as
// rtmGet does. RouteMessage.Marshal writes every address as a full-size
// sockaddr, not in the kernel's compact form; rtmKernelMessage builds that
// form.
func parseRTMFixture(t *testing.T, msgs ...*route.RouteMessage) []route.Message {
	t.Helper()
	var b []byte
	for _, m := range msgs {
		mb, err := m.Marshal()
		require.NoError(t, err)
		b = append(b, mb...)
	}
	parsed, err := route.ParseRIB(route.RIBTypeRoute, b)
	require.NoError(t, err)
	require.Len(t, parsed, len(msgs))
	return parsed
}

// rtmKernelMessage builds an RTM_GET reply of pid 100 and seq 7 the way
// the kernel writes it: an rt_msghdr of hdrLen bytes, whose fields up to
// rtm_seq darwin and FreeBSD lay out alike, followed by body, the
// addresses of the addrs bitmask in kernel form.
func rtmKernelMessage(hdrLen, flags, index, addrs int, body []byte) []byte {
	b := make([]byte, hdrLen, hdrLen+len(body))
	binary.NativeEndian.PutUint16(b[0:2], uint16(hdrLen+len(body)))
	b[2] = unix.RTM_VERSION
	b[3] = unix.RTM_GET
	binary.NativeEndian.PutUint16(b[4:6], uint16(index))
	binary.NativeEndian.PutUint32(b[8:12], uint32(flags))
	binary.NativeEndian.PutUint32(b[12:16], uint32(addrs))
	binary.NativeEndian.PutUint32(b[16:20], 100)
	binary.NativeEndian.PutUint32(b[20:24], 7)
	return append(b, body...)
}

// kernelRouteFromBytes parses b, one routing socket read, and reads the
// route to dst from its RTM_GET reply of pid 100 and seq 7.
func kernelRouteFromBytes(t *testing.T, b []byte, dst string) kernelRoute {
	t.Helper()
	msgs, err := route.ParseRIB(route.RIBTypeRoute, b)
	require.NoError(t, err)
	m := matchRTMReply(msgs, 100, 7)
	require.NotNil(t, m)
	kr, err := kernelRouteFromReply(m, netip.MustParseAddr(dst))
	require.NoError(t, err)
	return kr
}

// rtmReply returns an RTM_GET reply of pid 100 and seq 7.
func rtmReply(flags, index int, addrs ...route.Addr) *route.RouteMessage {
	return &route.RouteMessage{
		Version: unix.RTM_VERSION,
		Type:    unix.RTM_GET,
		Flags:   flags,
		Index:   index,
		ID:      100,
		Seq:     7,
		Addrs:   addrs,
	}
}

// rtmAddrs returns a routing socket address list from the addresses of
// dst, gateway, netmask, ifp and ifa, any of which may be nil.
func rtmAddrs(dst, gateway, netmask, ifp, ifa route.Addr) []route.Addr {
	addrs := make([]route.Addr, unix.RTAX_IFA+1)
	addrs[unix.RTAX_DST] = dst
	addrs[unix.RTAX_GATEWAY] = gateway
	addrs[unix.RTAX_NETMASK] = netmask
	addrs[unix.RTAX_IFP] = ifp
	addrs[unix.RTAX_IFA] = ifa
	return addrs
}

func inet4(s string) *route.Inet4Addr {
	return &route.Inet4Addr{IP: netip.MustParseAddr(s).As4()}
}

func inet6(s string) *route.Inet6Addr {
	return &route.Inet6Addr{IP: netip.MustParseAddr(s).As16()}
}

func TestMatchRTMReply(t *testing.T) {
	other := rtmReply(unix.RTF_UP, 4)
	other.ID = 200
	oldSeq := rtmReply(unix.RTF_UP, 4)
	oldSeq.Seq = 6
	change := rtmReply(unix.RTF_UP, 4)
	change.Type = unix.RTM_CHANGE
	ours := rtmReply(unix.RTF_UP|unix.RTF_GATEWAY, 5)

	msgs := parseRTMFixture(t, other, oldSeq, change, ours)
	got := matchRTMReply(msgs, 100, 7)
	require.NotNil(t, got)
	assert.Equal(t, 5, got.Index)

	assert.Nil(t, matchRTMReply(msgs[:3], 100, 7))
}

func TestKernelRouteFromReply(t *testing.T) {
	en0 := &route.LinkAddr{Index: 4, Name: "en0"}
	utun := &route.LinkAddr{Index: 20, Name: "utun4"}
	upGw := unix.RTF_UP | unix.RTF_GATEWAY

	tcs := []struct {
		name string
		dst  string
		m    *route.RouteMessage
		want kernelRoute
	}{
		{
			name: "ipv4 default via gateway",
			dst:  "192.0.2.1",
			m: rtmReply(upGw|unix.RTF_STATIC, 4, rtmAddrs(
				inet4("0.0.0.0"), inet4("192.168.1.1"), inet4("0.0.0.0"),
				en0, inet4("192.168.1.11"),
			)...),
			want: kernelRoute{
				ifIndex: 4,
				gateway: netip.MustParseAddr("192.168.1.1"),
				src:     netip.MustParseAddr("192.168.1.11"),
			},
		},
		{
			name: "link-layer gateway is an interface route",
			dst:  "192.0.2.1",
			m: rtmReply(upGw, 20, rtmAddrs(
				inet4("0.0.0.0"), &route.LinkAddr{Index: 20}, nil,
				utun, inet4("10.8.0.2"),
			)...),
			want: kernelRoute{
				ifIndex: 20,
				src:     netip.MustParseAddr("10.8.0.2"),
			},
		},
		{
			name: "ip gateway without RTF_GATEWAY is an interface route",
			dst:  "127.0.0.1",
			m: rtmReply(unix.RTF_UP|unix.RTF_HOST, 1, rtmAddrs(
				inet4("127.0.0.1"), inet4("127.0.0.1"), nil,
				&route.LinkAddr{Index: 1, Name: "lo0"}, inet4("127.0.0.1"),
			)...),
			want: kernelRoute{
				ifIndex: 1,
				src:     netip.MustParseAddr("127.0.0.1"),
			},
		},
		{
			name: "interface index from the message when ifp is missing",
			dst:  "192.0.2.1",
			m: rtmReply(upGw, 4, rtmAddrs(
				inet4("0.0.0.0"), inet4("192.168.1.1"), nil, nil, nil,
			)...),
			want: kernelRoute{
				ifIndex: 4,
				gateway: netip.MustParseAddr("192.168.1.1"),
			},
		},
		{
			name: "ifp index wins over the message index",
			dst:  "192.0.2.1",
			m: rtmReply(upGw, 1, rtmAddrs(
				inet4("0.0.0.0"), inet4("192.168.1.1"), nil, en0, nil,
			)...),
			want: kernelRoute{
				ifIndex: 4,
				gateway: netip.MustParseAddr("192.168.1.1"),
			},
		},
		{
			name: "ipv6 link-local gateway loses its zone",
			dst:  "2001:db8::1",
			m: rtmReply(upGw, 4, rtmAddrs(
				inet6("::"),
				&route.Inet6Addr{
					IP:     netip.MustParseAddr("fe80::1").As16(),
					ZoneID: 4,
				},
				inet6("::"),
				en0,
				inet6("2001:db8:1::2"),
			)...),
			want: kernelRoute{
				ifIndex: 4,
				gateway: netip.MustParseAddr("fe80::1"),
				src:     netip.MustParseAddr("2001:db8:1::2"),
			},
		},
		{
			name: "link-local interface address is no source",
			dst:  "2001:db8::1",
			m: rtmReply(upGw, 4, rtmAddrs(
				inet6("::"), inet6("fe80::1"), nil, en0, inet6("fe80::2"),
			)...),
			want: kernelRoute{
				ifIndex: 4,
				gateway: netip.MustParseAddr("fe80::1"),
			},
		},
		{
			name: "interface address of the other family is no source",
			dst:  "192.0.2.1",
			m: rtmReply(upGw, 4, rtmAddrs(
				inet4("0.0.0.0"), inet4("192.168.1.1"), nil, en0, inet6("2001:db8:1::2"),
			)...),
			want: kernelRoute{
				ifIndex: 4,
				gateway: netip.MustParseAddr("192.168.1.1"),
			},
		},
		{
			name: "ipv6 gateway with the scope embedded the KAME way",
			dst:  "2001:db8::1",
			m: rtmReply(upGw, 4, rtmAddrs(
				inet6("::"), inet6("fe80:4::1"), nil, en0, nil,
			)...),
			want: kernelRoute{
				ifIndex: 4,
				gateway: netip.MustParseAddr("fe80::1"),
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			msgs := parseRTMFixture(t, tc.m)
			m := matchRTMReply(msgs, 100, 7)
			require.NotNil(t, m)

			got, err := kernelRouteFromReply(m, netip.MustParseAddr(tc.dst))
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestKernelRouteFromReply_Errors(t *testing.T) {
	en0 := &route.LinkAddr{Index: 4, Name: "en0"}

	for _, flag := range []int{unix.RTF_REJECT, unix.RTF_BLACKHOLE} {
		m := rtmReply(unix.RTF_UP|flag, 4, rtmAddrs(
			inet4("0.0.0.0"), inet4("127.0.0.1"), nil, en0, nil,
		)...)
		_, err := kernelRouteFromReply(
			parseRTMFixture(t, m)[0].(*route.RouteMessage),
			netip.MustParseAddr("192.0.2.1"),
		)
		assert.ErrorIs(t, err, ErrNoIPv4Route)
	}

	m := rtmReply(unix.RTF_UP, 0, rtmAddrs(inet6("::"), nil, nil, nil, nil)...)
	_, err := kernelRouteFromReply(
		parseRTMFixture(t, m)[0].(*route.RouteMessage),
		netip.MustParseAddr("2001:db8::1"),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no output interface")
}

func TestRouteAddr(t *testing.T) {
	assert.Equal(t, inet4("192.0.2.1"), routeAddr(netip.MustParseAddr("192.0.2.1")))
	assert.Equal(t, inet6("2001:db8::1"), routeAddr(netip.MustParseAddr("2001:db8::1")))
}
