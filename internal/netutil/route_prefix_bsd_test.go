//go:build darwin || freebsd

package netutil

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// prefixFromBytes parses b, one routing socket read, and reads the prefix
// of the route to dst from its RTM_GET reply of pid 100 and seq 7.
func prefixFromBytes(t *testing.T, b []byte, dst string) (netip.Prefix, error) {
	t.Helper()
	msgs, err := route.ParseRIB(route.RIBTypeRoute, b)
	require.NoError(t, err)
	m := matchRTMReply(msgs, 100, 7)
	require.NotNil(t, m)
	return prefixFromReply(m, netip.MustParseAddr(dst))
}

func TestPrefixFromReply(t *testing.T) {
	en0 := &route.LinkAddr{Index: 4, Name: "en0"}
	upGw := unix.RTF_UP | unix.RTF_GATEWAY

	tcs := []struct {
		name string
		dst  string
		m    *route.RouteMessage
		want string
	}{
		{
			name: "default route",
			dst:  "10.0.0.1",
			m: rtmReply(upGw|unix.RTF_STATIC, 4, rtmAddrs(
				inet4("0.0.0.0"), inet4("192.168.1.1"), inet4("0.0.0.0"), en0, nil,
			)...),
			want: "0.0.0.0/0",
		},
		{
			name: "network route",
			dst:  "172.20.10.1",
			m: rtmReply(unix.RTF_UP|unix.RTF_STATIC, 20, rtmAddrs(
				inet4("172.20.10.0"), &route.LinkAddr{Index: 20}, inet4("255.255.255.0"),
				nil, nil,
			)...),
			want: "172.20.10.0/24",
		},
		{
			name: "host route",
			dst:  "10.0.0.2",
			m: rtmReply(upGw|unix.RTF_HOST, 4, rtmAddrs(
				inet4("10.0.0.2"), inet4("192.168.1.1"), nil, en0, nil,
			)...),
			want: "10.0.0.2/32",
		},
		{
			name: "host flag wins over a netmask",
			dst:  "10.0.0.2",
			m: rtmReply(upGw|unix.RTF_HOST, 4, rtmAddrs(
				inet4("10.0.0.2"), inet4("192.168.1.1"), inet4("255.0.0.0"), en0, nil,
			)...),
			want: "10.0.0.2/32",
		},
		{
			name: "ipv6 network route",
			dst:  "2001:db8::1",
			m: rtmReply(upGw, 4, rtmAddrs(
				inet6("2001:db8::"), inet6("fe80::1"), inet6("ffff:ffff::"), en0, nil,
			)...),
			want: "2001:db8::/32",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			m := matchRTMReply(parseRTMFixture(t, tc.m), 100, 7)
			require.NotNil(t, m)

			got, err := prefixFromReply(m, netip.MustParseAddr(tc.dst))
			require.NoError(t, err)
			assert.Equal(t, netip.MustParsePrefix(tc.want), got)
		})
	}
}

func TestPrefixFromReply_Errors(t *testing.T) {
	en0 := &route.LinkAddr{Index: 4, Name: "en0"}
	dst := netip.MustParseAddr("10.0.0.1")

	for _, flag := range []int{unix.RTF_REJECT, unix.RTF_BLACKHOLE} {
		m := rtmReply(unix.RTF_UP|flag, 4, rtmAddrs(
			inet4("10.0.0.0"), inet4("127.0.0.1"), inet4("255.0.0.0"), en0, nil,
		)...)
		_, err := prefixFromReply(parseRTMFixture(t, m)[0].(*route.RouteMessage), dst)
		assert.ErrorIs(t, err, ErrNoIPv4Route, "flag %#x", flag)
		var reject *rejectRouteError
		require.ErrorAs(t, err, &reject, "flag %#x", flag)
		assert.Equal(t, netip.MustParsePrefix("10.0.0.0/8"), reject.prefix)
		assert.EqualError(t, err,
			"route lookup 10.0.0.1: no IPv4 default route (reject route 10.0.0.0/8)")
	}

	// A reject route without a readable netmask is no route of unknown
	// prefix.
	m := rtmReply(unix.RTF_UP|unix.RTF_BLACKHOLE, 4, rtmAddrs(
		inet4("10.0.0.0"), inet4("127.0.0.1"), nil, en0, nil,
	)...)
	_, err := prefixFromReply(parseRTMFixture(t, m)[0].(*route.RouteMessage), dst)
	assert.ErrorIs(t, err, ErrNoIPv4Route)
	var reject *rejectRouteError
	assert.NotErrorAs(t, err, &reject)

	tcs := []struct {
		name    string
		m       *route.RouteMessage
		wantMsg string
	}{
		{
			name: "no netmask on a network route",
			m: rtmReply(unix.RTF_UP, 4, rtmAddrs(
				inet4("10.0.0.0"), inet4("192.168.1.1"), nil, en0, nil,
			)...),
			wantMsg: "no netmask",
		},
		{
			name: "non-contiguous netmask",
			m: rtmReply(unix.RTF_UP, 4, rtmAddrs(
				inet4("10.0.0.0"), inet4("192.168.1.1"), inet4("255.0.255.0"), en0, nil,
			)...),
			wantMsg: "netmask 255.0.255.0 is not a prefix",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			m := matchRTMReply(parseRTMFixture(t, tc.m), 100, 7)
			require.NotNil(t, m)
			_, err := prefixFromReply(m, dst)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantMsg)
		})
	}
}
