package netutil

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestFindIfaceByGateway(t *testing.T) {
	en0 := net.Interface{Index: 1, Name: "en0", Flags: net.FlagUp}
	en1 := net.Interface{Index: 2, Name: "en1", Flags: net.FlagUp}
	en2Down := net.Interface{Index: 3, Name: "en2", Flags: 0}
	lo0 := net.Interface{
		Index: 4,
		Name:  "lo0",
		Flags: net.FlagUp | net.FlagLoopback,
	}

	tcs := []struct {
		name       string
		candidates []ifaceAddrs
		gateway    net.IP
		wantErr    bool
		wantIface  string
		wantLocal  string
	}{
		{
			name: "gateway on the only interface",
			candidates: []ifaceAddrs{
				{iface: en0, addrs: []net.Addr{ipNet("192.168.1.11/24")}},
			},
			gateway:   net.ParseIP("192.168.1.1"),
			wantIface: "en0",
			wantLocal: "192.168.1.11",
		},
		{
			name: "picks the interface whose subnet contains the gateway",
			candidates: []ifaceAddrs{
				{iface: en0, addrs: []net.Addr{ipNet("10.0.0.5/24")}},
				{iface: en1, addrs: []net.Addr{ipNet("192.168.1.11/24")}},
			},
			gateway:   net.ParseIP("192.168.1.1"),
			wantIface: "en1",
			wantLocal: "192.168.1.11",
		},
		{
			name: "picks the matching address among several",
			candidates: []ifaceAddrs{
				{iface: en0, addrs: []net.Addr{
					ipNet("fe80::1/64"),
					ipNet("10.0.0.5/24"),
					ipNet("192.168.1.11/24"),
				}},
			},
			gateway:   net.ParseIP("192.168.1.1"),
			wantIface: "en0",
			wantLocal: "192.168.1.11",
		},
		{
			name: "accepts a gateway in 16-byte form",
			candidates: []ifaceAddrs{
				{iface: en0, addrs: []net.Addr{ipNet("192.168.1.11/24")}},
			},
			gateway:   net.IPv4(192, 168, 1, 1),
			wantIface: "en0",
			wantLocal: "192.168.1.11",
		},
		{
			name: "skips interfaces that are down",
			candidates: []ifaceAddrs{
				{iface: en2Down, addrs: []net.Addr{ipNet("192.168.1.11/24")}},
				{iface: en1, addrs: []net.Addr{ipNet("192.168.1.12/24")}},
			},
			gateway:   net.ParseIP("192.168.1.1"),
			wantIface: "en1",
			wantLocal: "192.168.1.12",
		},
		{
			name: "skips loopback interfaces",
			candidates: []ifaceAddrs{
				{iface: lo0, addrs: []net.Addr{ipNet("192.168.1.11/24")}},
				{iface: en0, addrs: []net.Addr{ipNet("192.168.1.12/24")}},
			},
			gateway:   net.ParseIP("192.168.1.1"),
			wantIface: "en0",
			wantLocal: "192.168.1.12",
		},
		{
			name: "gateway is the interface's own address",
			candidates: []ifaceAddrs{
				{iface: en0, addrs: []net.Addr{ipNet("192.168.1.11/24")}},
			},
			gateway: net.ParseIP("192.168.1.11"),
			wantErr: true,
		},
		{
			name: "point-to-point address does not contain the peer",
			candidates: []ifaceAddrs{
				{iface: en0, addrs: []net.Addr{ipNet("10.8.0.2/32")}},
			},
			gateway: net.ParseIP("10.8.0.1"),
			wantErr: true,
		},
		{
			name: "no interface on the gateway subnet",
			candidates: []ifaceAddrs{
				{iface: en0, addrs: []net.Addr{ipNet("10.0.0.5/24")}},
			},
			gateway: net.ParseIP("192.168.1.1"),
			wantErr: true,
		},
		{
			name: "ipv6 gateway",
			candidates: []ifaceAddrs{
				{iface: en0, addrs: []net.Addr{ipNet("fe80::2/64")}},
			},
			gateway: net.ParseIP("fe80::1"),
			wantErr: true,
		},
		{
			name:       "no candidates",
			candidates: nil,
			gateway:    net.ParseIP("192.168.1.1"),
			wantErr:    true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			iface, localIP, err := findIfaceByGateway(tc.candidates, tc.gateway)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.wantIface, iface.Name)
			assert.Equal(t, tc.wantLocal, localIP.String())
		})
	}
}

func TestFindIfaceByGateway_IPv6(t *testing.T) {
	en0 := net.Interface{Index: 1, Name: "en0", Flags: net.FlagUp}
	candidates := []ifaceAddrs{
		{iface: en0, addrs: []net.Addr{ipNet("2001:db8::2/64")}},
	}

	for _, gateway := range []string{"fe80::1", "2001:db8::1"} {
		_, _, err := findIfaceByGateway(candidates, net.ParseIP(gateway))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "IPv6 gateways are not supported yet")
	}
}

// fakeDiscovery makes RouteTo return kr, or err when it is not nil, and the
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

func TestDiscoverRoute_Nil(t *testing.T) {
	en0 := net.Interface{Index: 1, Name: "en0", Flags: net.FlagUp}
	lanAddrs := []net.Addr{ipNet("fe80::1/64"), ipNet("192.168.1.11/24")}

	tcs := []struct {
		name    string
		kr      kernelRoute
		err     error
		addrs   []net.Addr
		wantErr error
		wantMsg string
		assert  func(t *testing.T, r *Route)
	}{
		{
			name: "gateway route uses the route's source address",
			kr: kernelRoute{
				ifIndex: 1,
				gateway: netip.MustParseAddr("192.168.1.1"),
				src:     netip.MustParseAddr("192.168.1.12"),
			},
			addrs: lanAddrs,
			assert: func(t *testing.T, r *Route) {
				assert.Equal(t, FamilyV4, r.Family)
				assert.Equal(t, "en0", r.Iface.Name)
				assert.Equal(t, "192.168.1.1", r.Gateway.String())
				assert.Equal(t, "192.168.1.12", r.LocalIP.String())
			},
		},
		{
			name: "missing source falls back to the interface address",
			kr: kernelRoute{
				ifIndex: 1,
				gateway: netip.MustParseAddr("192.168.1.1"),
			},
			addrs: lanAddrs,
			assert: func(t *testing.T, r *Route) {
				assert.Equal(t, "192.168.1.11", r.LocalIP.String())
			},
		},
		{
			name:    "interface route has no gateway",
			kr:      kernelRoute{ifIndex: 1},
			addrs:   lanAddrs,
			wantErr: ErrNoGateway,
			wantMsg: "route to 192.0.2.1 goes through en0 without a gateway",
		},
		{
			name:    "no route",
			err:     errNoRoute(probeDstV4),
			wantErr: ErrNoIPv4Route,
		},
		{
			name: "interface without an IPv4 address",
			kr: kernelRoute{
				ifIndex: 1,
				gateway: netip.MustParseAddr("192.168.1.1"),
			},
			addrs:   []net.Addr{ipNet("fe80::1/64")},
			wantMsg: "interface en0 has no IPv4 address",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			fakeDiscovery(t, tc.kr, tc.err, en0, tc.addrs)

			route, err := DiscoverRoute(nil)
			if tc.wantErr != nil || tc.wantMsg != "" {
				require.Error(t, err)
				if tc.wantErr != nil {
					assert.ErrorIs(t, err, tc.wantErr)
				}
				assert.ErrorContains(t, err, tc.wantMsg)
				return
			}

			require.NoError(t, err)
			tc.assert(t, route)
		})
	}
}

func TestDiscoverRoute_InterfaceRouteIsNotNoIPv4Route(t *testing.T) {
	fakeDiscovery(
		t,
		kernelRoute{ifIndex: 1},
		nil,
		net.Interface{Index: 1, Name: "utun4"},
		[]net.Addr{ipNet("10.8.0.2/32")},
	)

	_, err := DiscoverRoute(nil)
	require.ErrorIs(t, err, ErrNoGateway)
	assert.NotErrorIs(t, err, ErrNoIPv4Route)
}

func TestDiscoverInterface(t *testing.T) {
	utun := net.Interface{Index: 7, Name: "utun4", Flags: net.FlagUp}

	t.Run("interface route needs no gateway", func(t *testing.T) {
		fakeDiscovery(
			t,
			kernelRoute{ifIndex: 7},
			nil,
			utun,
			[]net.Addr{ipNet("10.8.0.2/32")},
		)

		iface, localIP, err := DiscoverInterface()
		require.NoError(t, err)
		assert.Equal(t, "utun4", iface.Name)
		assert.Equal(t, "10.8.0.2", localIP.String())
	})

	t.Run("no route", func(t *testing.T) {
		fakeDiscovery(t, kernelRoute{}, errNoRoute(probeDstV4), utun, nil)

		_, _, err := DiscoverInterface()
		require.ErrorIs(t, err, ErrNoIPv4Route)
	})

	t.Run("no IPv4 address", func(t *testing.T) {
		fakeDiscovery(t, kernelRoute{ifIndex: 7}, nil, utun, nil)

		_, _, err := DiscoverInterface()
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
			route: Route{Family: FamilyV4, Gateway: net.ParseIP("192.168.1.1")},
			want:  "192.168.1.1",
		},
		{
			name:  "ipv6 global",
			route: Route{Family: FamilyV6, Gateway: net.ParseIP("2001:db8::1")},
			want:  "2001:db8::1",
		},
		{
			name: "ipv6 link-local with zone",
			route: Route{
				Family:  FamilyV6,
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
