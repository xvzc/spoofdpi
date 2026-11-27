package route

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/netutil"
)

// ipNet parses cidr into an interface address, keeping the host part
// (e.g. 192.168.1.11/24) the way net.Interface.Addrs reports it.
func ipNet(cidr string) *net.IPNet {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	ipnet.IP = ip
	return ipnet
}

// fakeDiscovery makes Lookup return kr, or err when it is not nil, and the
// interface lookup return iface.
func fakeDiscovery(
	t *testing.T,
	kr kernelRoute,
	err error,
	iface net.Interface,
	addrs []net.Addr,
) {
	t.Helper()
	origRoute, origIface, origAddrs := osRouteTo, interfaceByIndex, addrsOf
	t.Cleanup(func() {
		osRouteTo, interfaceByIndex, addrsOf = origRoute, origIface, origAddrs
	})
	osRouteTo = func(netip.Addr) (kernelRoute, error) { return kr, err }
	interfaceByIndex = func(int) (*net.Interface, error) { return &iface, nil }
	addrsOf = func(*net.Interface) ([]net.Addr, error) { return addrs, nil }
}

func TestInternetInterface(t *testing.T) {
	utun := net.Interface{Index: 7, Name: "utun4", Flags: net.FlagUp}

	t.Run("interface route needs no gateway", func(t *testing.T) {
		fakeDiscovery(
			t,
			kernelRoute{ifIndex: 7},
			nil,
			utun,
			[]net.Addr{ipNet("10.8.0.2/32")},
		)

		iface, localIP, err := InternetInterface()
		require.NoError(t, err)
		assert.Equal(t, "utun4", iface.Name)
		assert.Equal(t, "10.8.0.2", localIP.String())
	})

	t.Run("no route", func(t *testing.T) {
		fakeDiscovery(t, kernelRoute{}, errNoRoute(probeDstV4), utun, nil)

		_, _, err := InternetInterface()
		require.ErrorIs(t, err, ErrNoIPv4)
	})

	t.Run("no IPv4 address", func(t *testing.T) {
		fakeDiscovery(t, kernelRoute{ifIndex: 7}, nil, utun, nil)

		_, _, err := InternetInterface()
		assert.ErrorContains(t, err, "interface utun4 has no IPv4 address")
	})
}

func TestRoute_GatewayString(t *testing.T) {
	tcs := []struct {
		name  string
		route Route
		want  string
	}{
		{
			name:  "ipv4",
			route: Route{Family: netutil.FamilyV4, Gateway: net.ParseIP("192.168.1.1")},
			want:  "192.168.1.1",
		},
		{
			name:  "ipv6 global",
			route: Route{Family: netutil.FamilyV6, Gateway: net.ParseIP("2001:db8::1")},
			want:  "2001:db8::1",
		},
		{
			name: "ipv6 link-local with zone",
			route: Route{
				Family:  netutil.FamilyV6,
				Gateway: net.ParseIP("fe80::1"),
				Zone:    "en0",
			},
			want: "fe80::1%en0",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.route.GatewayString())
		})
	}
}
