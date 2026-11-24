package netutil

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeRoute is a route of a fake routing table: a prefix, and the error a
// lookup that matches it returns, such as no route for a blackhole the way
// Linux reports it. reject makes it a reject route whose prefix the kernel
// reports, as darwin and FreeBSD do.
type fakeRoute struct {
	prefix string
	err    error
	reject bool
}

// fakePrefixOf returns a route prefix lookup over routes and a default
// route, which matches the longest prefix the way the kernel does.
func fakePrefixOf(routes ...fakeRoute) func(netip.Addr) (netip.Prefix, error) {
	table := append([]fakeRoute{{prefix: "0.0.0.0/0"}}, routes...)
	return func(dst netip.Addr) (netip.Prefix, error) {
		var best netip.Prefix
		var bestRoute fakeRoute
		for _, r := range table {
			p := netip.MustParsePrefix(r.prefix)
			if p.Contains(dst) && (!best.IsValid() || p.Bits() > best.Bits()) {
				best, bestRoute = p, r
			}
		}
		if bestRoute.reject {
			return netip.Prefix{}, &rejectRouteError{prefix: best, err: errNoRoute(dst)}
		}
		if bestRoute.err != nil {
			return netip.Prefix{}, bestRoute.err
		}
		return best, nil
	}
}

func cidrTestAddrs(cidrs ...string) []net.Addr {
	addrs := make([]net.Addr, 0, len(cidrs))
	for _, c := range cidrs {
		ip, n, err := net.ParseCIDR(c)
		if err != nil {
			panic(err)
		}
		n.IP = ip
		addrs = append(addrs, n)
	}
	return addrs
}

// countLookups returns prefixOf and the count of lookups it has made.
func countLookups(
	prefixOf func(netip.Addr) (netip.Prefix, error),
) (func(netip.Addr) (netip.Prefix, error), *int) {
	n := new(int)
	return func(dst netip.Addr) (netip.Prefix, error) {
		*n++
		return prefixOf(dst)
	}, n
}

func TestFindSafeCIDR(t *testing.T) {
	blackhole := errNoRoute(netip.MustParseAddr("10.0.0.1"))

	tcs := []struct {
		name     string
		addrs    []net.Addr
		prefixOf func(netip.Addr) (netip.Prefix, error)
		want     string
		// wantLookups, when not 0, is the number of route lookups,
		// the probe's included.
		wantLookups int
	}{
		{
			name:     "no routes but the default",
			prefixOf: fakePrefixOf(),
			want:     "10.0.0.0/30",
		},
		{
			name:     "interface network",
			addrs:    cidrTestAddrs("10.0.0.5/24", "127.0.0.1/8", "fe80::1/64"),
			prefixOf: fakePrefixOf(fakeRoute{prefix: "10.0.0.0/24"}),
			want:     "10.0.1.0/30",
		},
		{
			name: "interface address with a non-prefix mask is its address alone",
			addrs: []net.Addr{
				&net.IPNet{IP: net.IPv4(10, 0, 0, 1), Mask: net.IPv4Mask(255, 0, 255, 0)},
			},
			prefixOf: fakePrefixOf(),
			want:     "10.0.0.4/30",
		},
		{
			name:     "a VPN route to 10.0.0.0/16 is skipped",
			prefixOf: fakePrefixOf(fakeRoute{prefix: "10.0.0.0/16"}),
			want:     "10.1.0.0/30",
		},
		{
			name:     "10.0.0.0/8 taken moves to 172.16.0.0/12",
			prefixOf: fakePrefixOf(fakeRoute{prefix: "10.0.0.0/8"}),
			want:     "172.16.0.0/30",
		},
		{
			name:  "10.0.0.0/8 and 172.16.0.0/12 taken moves to 192.168.0.0/16",
			addrs: cidrTestAddrs("172.20.0.114/12"),
			prefixOf: fakePrefixOf(
				fakeRoute{prefix: "10.0.0.0/8"},
				fakeRoute{prefix: "172.16.0.0/12"},
			),
			want: "192.168.0.0/30",
		},
		{
			name: "only 198.18.0.0/15 left",
			prefixOf: fakePrefixOf(
				fakeRoute{prefix: "10.0.0.0/8"},
				fakeRoute{prefix: "172.16.0.0/12"},
				fakeRoute{prefix: "192.168.0.0/16"},
			),
			want: "198.18.0.0/30",
		},
		{
			name:     "a route wider than a range skips it",
			prefixOf: fakePrefixOf(fakeRoute{prefix: "8.0.0.0/5"}),
			want:     "172.16.0.0/30",
		},
		{
			name: "full-tunnel VPN /1 halves are no conflict",
			prefixOf: fakePrefixOf(
				fakeRoute{prefix: "0.0.0.0/1"},
				fakeRoute{prefix: "128.0.0.0/1"},
			),
			want: "10.0.0.0/30",
		},
		{
			name:     "host route to the remote address",
			prefixOf: fakePrefixOf(fakeRoute{prefix: "10.0.0.2/32"}),
			want:     "10.0.0.4/30",
		},
		{
			name:     "host route to the network address is no conflict",
			prefixOf: fakePrefixOf(fakeRoute{prefix: "10.0.0.0/32"}),
			want:     "10.0.0.0/30",
		},
		{
			name: "blackhole route is a conflict",
			prefixOf: fakePrefixOf(
				fakeRoute{prefix: "10.0.0.0/29", err: blackhole},
			),
			want: "10.0.0.8/30",
		},
		{
			name: "reject route with its prefix over 10.0.0.0/8 is jumped in one step",
			prefixOf: fakePrefixOf(
				fakeRoute{prefix: "10.0.0.0/8", reject: true},
			),
			want: "172.16.0.0/30",
			// The probe, 10.0.0.1, and 172.16.0.1 and .2.
			wantLookups: 4,
		},
		{
			name: "errno-only blackhole over 10.0.0.0/8 gives up on it after the bound",
			prefixOf: fakePrefixOf(
				fakeRoute{prefix: "10.0.0.0/8", err: blackhole},
			),
			want: "172.16.0.0/30",
			// The probe, the .1 of each candidate up to the bound, and
			// 172.16.0.1 and .2.
			wantLookups: 1 + tunMaxNoRouteRun + 2,
		},
		{
			name: "another conflict resets the no-route run",
			prefixOf: fakePrefixOf(
				fakeRoute{prefix: "10.0.0.0/8", err: blackhole},
				fakeRoute{prefix: "10.0.3.252/30"},
			),
			want: "172.16.0.0/30",
			// The probe, 255 candidates without a route, the routed
			// 10.0.3.252/30, a new run of the bound, and 172.16.0.1 and .2.
			wantLookups: 1 + 255 + 1 + tunMaxNoRouteRun + 2,
		},
		{
			name:  "probe /32 checks interface addresses only",
			addrs: cidrTestAddrs("10.0.0.1/30"),
			prefixOf: func(dst netip.Addr) (netip.Prefix, error) {
				if dst == probeDstV4 {
					return netip.PrefixFrom(dst, 32), nil
				}
				return netip.Prefix{}, errors.New("candidate looked up")
			},
			want: "10.0.0.4/30",
		},
		{
			name:  "probe without a route checks interface addresses only",
			addrs: cidrTestAddrs("10.0.0.1/30"),
			prefixOf: func(dst netip.Addr) (netip.Prefix, error) {
				if dst == probeDstV4 {
					return netip.Prefix{}, errNoRoute(dst)
				}
				return netip.Prefix{}, errors.New("candidate looked up")
			},
			want:        "10.0.0.4/30",
			wantLookups: 1,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			prefixOf, lookups := countLookups(tc.prefixOf)
			got, err := findSafeCIDR(tc.addrs, prefixOf)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
			if tc.wantLookups != 0 {
				assert.Equal(t, tc.wantLookups, *lookups)
			}
		})
	}
}

func TestFindSafeCIDR_Errors(t *testing.T) {
	lookupErr := errors.New("netlink: no reply")

	tcs := []struct {
		name     string
		addrs    []net.Addr
		prefixOf func(netip.Addr) (netip.Prefix, error)
		wantErr  error
		wantMsg  string
	}{
		{
			name: "probe lookup fails",
			prefixOf: func(dst netip.Addr) (netip.Prefix, error) {
				return netip.Prefix{}, fmt.Errorf("route lookup %s: %w", dst, lookupErr)
			},
			wantErr: lookupErr,
			wantMsg: "route lookup 192.0.2.1: netlink: no reply",
		},
		{
			name: "candidate lookup fails",
			prefixOf: fakePrefixOf(
				fakeRoute{prefix: "10.0.0.0/8", err: lookupErr},
			),
			wantErr: lookupErr,
			wantMsg: "netlink: no reply",
		},
		{
			name:  "every range taken",
			addrs: cidrTestAddrs("192.168.1.10/16"),
			prefixOf: fakePrefixOf(
				fakeRoute{prefix: "10.0.0.0/8"},
				fakeRoute{prefix: "172.16.0.0/12"},
				fakeRoute{prefix: "198.18.0.0/15"},
			),
			wantMsg: "no free /30 for the TUN interface in 10.0.0.0/8, " +
				"172.16.0.0/12, 192.168.0.0/16 or 198.18.0.0/15: every candidate " +
				"overlaps an interface address or a more specific route " +
				"(last: 198.18.0.0/30 is routed by 198.18.0.0/15, more specific " +
				"than 0.0.0.0/0)",
		},
		{
			name:  "every range taken, the last one by an errno-only blackhole",
			addrs: cidrTestAddrs("192.168.1.10/16"),
			prefixOf: fakePrefixOf(
				fakeRoute{prefix: "10.0.0.0/8"},
				fakeRoute{prefix: "172.16.0.0/12"},
				fakeRoute{
					prefix: "198.18.0.0/15",
					err:    errNoRoute(netip.MustParseAddr("198.18.0.1")),
				},
			),
			wantMsg: "no free /30 for the TUN interface in 10.0.0.0/8, " +
				"172.16.0.0/12, 192.168.0.0/16 or 198.18.0.0/15: every candidate " +
				"overlaps an interface address or a more specific route " +
				"(last: 198.18.0.0/15: 256 candidates in a row have no route)",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			_, err := findSafeCIDR(tc.addrs, tc.prefixOf)
			require.Error(t, err)
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
			}
			assert.EqualError(t, err, tc.wantMsg)
		})
	}
}

// TestFindSafeCIDR_Seam checks that FindSafeCIDR looks routes up through
// osRoutePrefix and checks the host's interface addresses.
func TestFindSafeCIDR_Seam(t *testing.T) {
	orig := osRoutePrefix
	t.Cleanup(func() { osRoutePrefix = orig })
	var lookups []netip.Addr
	osRoutePrefix = func(dst netip.Addr) (netip.Prefix, error) {
		lookups = append(lookups, dst)
		return netip.MustParsePrefix("0.0.0.0/0"), nil
	}

	got, err := FindSafeCIDR()
	require.NoError(t, err)
	subnet := netip.MustParsePrefix(got)
	assert.Equal(t, tunSubnetBits, subnet.Bits())
	require.NotEmpty(t, lookups)
	assert.Equal(t, probeDstV4, lookups[0])

	addrs, err := net.InterfaceAddrs()
	require.NoError(t, err)
	for _, n := range interfaceNetsV4(addrs) {
		assert.False(t, n.Overlaps(subnet), "%s overlaps %s", got, n)
	}
}

func TestLastAddrV4(t *testing.T) {
	tcs := []struct {
		prefix string
		want   string
	}{
		{"10.0.0.0/30", "10.0.0.3"},
		{"10.1.2.3/8", "10.255.255.255"},
		{"10.0.0.2/32", "10.0.0.2"},
		{"0.0.0.0/0", "255.255.255.255"},
	}

	for _, tc := range tcs {
		t.Run(tc.prefix, func(t *testing.T) {
			got := lastAddrV4(netip.MustParsePrefix(tc.prefix))
			assert.Equal(t, netip.MustParseAddr(tc.want), got)
		})
	}
}
