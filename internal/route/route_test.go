package route

import (
	"errors"
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
			name: "ipv6 gateway on a global subnet",
			candidates: []ifaceAddrs{
				{iface: en0, addrs: []net.Addr{
					ipNet("192.168.1.11/24"),
					ipNet("fe80::2/64"),
					ipNet("2001:db8::2/64"),
				}},
			},
			gateway:   net.ParseIP("2001:db8::1"),
			wantIface: "en0",
			wantLocal: "2001:db8::2",
		},
		{
			name: "ipv6 gateway on a unique local subnet",
			candidates: []ifaceAddrs{
				{iface: en0, addrs: []net.Addr{ipNet("2001:db8::2/64")}},
				{iface: en1, addrs: []net.Addr{ipNet("fd00:1::2/64")}},
			},
			gateway:   net.ParseIP("fd00:1::1"),
			wantIface: "en1",
			wantLocal: "fd00:1::2",
		},
		{
			name: "ipv6 link-local subnets are left out",
			candidates: []ifaceAddrs{
				{iface: en0, addrs: []net.Addr{ipNet("fe80::2/64")}},
			},
			gateway: net.ParseIP("fe80::1"),
			wantErr: true,
		},
		{
			name: "ipv6 gateway is the interface's own address",
			candidates: []ifaceAddrs{
				{iface: en0, addrs: []net.Addr{ipNet("2001:db8::2/64")}},
			},
			gateway: net.ParseIP("2001:db8::2"),
			wantErr: true,
		},
		{
			name: "ipv4 subnet does not take an ipv6 gateway",
			candidates: []ifaceAddrs{
				{iface: en0, addrs: []net.Addr{ipNet("0.0.0.0/0")}},
			},
			gateway: net.ParseIP("2001:db8::1"),
			wantErr: true,
		},
		{
			name: "ipv6 subnet does not take an ipv4 gateway",
			candidates: []ifaceAddrs{
				{iface: en0, addrs: []net.Addr{ipNet("::/0")}},
			},
			gateway: net.ParseIP("192.168.1.1"),
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
				assert.Equal(t, netutil.FamilyV4, r.Family)
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

func TestDiscoverRoute_IPv6Gateway(t *testing.T) {
	_, err := DiscoverRoute(net.ParseIP("2001:db8::1"))
	assert.ErrorContains(t, err, "gateway 2001:db8::1 is not an IPv4 address")
}

// fakeZoneInterfaces makes the interface lookups by name and by index
// resolve among ifaces.
func fakeZoneInterfaces(t *testing.T, ifaces ...net.Interface) {
	t.Helper()
	origName, origIndex := interfaceByName, interfaceByIndex
	t.Cleanup(func() { interfaceByName, interfaceByIndex = origName, origIndex })
	interfaceByName = func(name string) (*net.Interface, error) {
		for i := range ifaces {
			if ifaces[i].Name == name {
				return &ifaces[i], nil
			}
		}
		return nil, errors.New("no such network interface")
	}
	interfaceByIndex = func(index int) (*net.Interface, error) {
		for i := range ifaces {
			if ifaces[i].Index == index {
				return &ifaces[i], nil
			}
		}
		return nil, errors.New("no such network interface")
	}
}

func TestDiscoverRoute6(t *testing.T) {
	en0 := net.Interface{Index: 4, Name: "en0", Flags: net.FlagUp}
	en1 := net.Interface{Index: 5, Name: "en1", Flags: net.FlagUp}
	en2Down := net.Interface{Index: 6, Name: "en2"}
	lo0 := net.Interface{Index: 1, Name: "lo0", Flags: net.FlagUp | net.FlagLoopback}
	llGw, globalGw := net.ParseIP("fe80::1"), net.ParseIP("2001:db8::1")

	tcs := []struct {
		name      string
		kr        kernelRoute
		routeErr  error
		gateway   net.IP
		zone      string
		want      *Route
		wantErrIs error
		wantMsg   string
	}{
		{
			name: "discovered link-local gateway gets the zone and source",
			kr: kernelRoute{
				ifIndex: 4,
				gateway: netip.MustParseAddr("fe80::1"),
				src:     netip.MustParseAddr("2001:db8::2"),
			},
			want: &Route{
				Family:  netutil.FamilyV6,
				Iface:   en0,
				LocalIP: net.IP(netip.MustParseAddr("2001:db8::2").AsSlice()),
				Gateway: net.IP(netip.MustParseAddr("fe80::1").AsSlice()),
				Zone:    "en0",
			},
		},
		{
			name: "discovered global gateway has no zone",
			kr:   kernelRoute{ifIndex: 5, gateway: netip.MustParseAddr("2001:db8::1")},
			want: &Route{
				Family:  netutil.FamilyV6,
				Iface:   en1,
				Gateway: net.IP(netip.MustParseAddr("2001:db8::1").AsSlice()),
			},
		},
		{
			name: "discovered interface route has no gateway",
			kr:   kernelRoute{ifIndex: 4},
			want: &Route{Family: netutil.FamilyV6, Iface: en0},
		},
		{
			name:      "no route",
			routeErr:  errNoRoute(probeDstV6),
			wantErrIs: ErrNoIPv6Route,
		},
		{
			name:    "zone by name",
			gateway: llGw,
			zone:    "en1",
			want:    &Route{Family: netutil.FamilyV6, Iface: en1, Gateway: llGw, Zone: "en1"},
		},
		{
			name:    "zone by index",
			gateway: llGw,
			zone:    "5",
			want:    &Route{Family: netutil.FamilyV6, Iface: en1, Gateway: llGw, Zone: "en1"},
		},
		{
			name:    "unknown zone",
			gateway: llGw,
			zone:    "en9",
			wantMsg: `gateway fe80::1: zone "en9"`,
		},
		{
			name:    "zone of an interface that is down",
			gateway: llGw,
			zone:    "en2",
			wantMsg: "interface en2 is down",
		},
		{
			name:    "zone of a loopback",
			gateway: llGw,
			zone:    "lo0",
			wantMsg: "interface lo0 is a loopback",
		},
		{
			name:    "zone on a global gateway",
			gateway: globalGw,
			zone:    "en0",
			wantMsg: "a zone is allowed only on a link-local address",
		},
		{
			name:    "link-local gateway without a zone takes the route's interface",
			kr:      kernelRoute{ifIndex: 5},
			gateway: llGw,
			want:    &Route{Family: netutil.FamilyV6, Iface: en1, Gateway: llGw, Zone: "en1"},
		},
		{
			name:      "link-local gateway without a zone or a route",
			routeErr:  errNoRoute(probeDstV6),
			gateway:   llGw,
			wantErrIs: ErrNoIPv6Route,
			wantMsg:   "link-local gateway fe80::1: ",
		},
		{
			name:    "ipv4 gateway",
			gateway: net.ParseIP("192.168.1.1"),
			wantMsg: "gateway 192.168.1.1 is not an IPv6 address",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			fakeDiscovery(t, tc.kr, tc.routeErr, en0, nil)
			fakeZoneInterfaces(t, lo0, en0, en1, en2Down)

			route, err := DiscoverRoute6(tc.gateway, tc.zone)
			if tc.want != nil {
				require.NoError(t, err)
				assert.Equal(t, tc.want, route)
				return
			}

			require.Error(t, err)
			if tc.wantErrIs != nil {
				assert.ErrorIs(t, err, tc.wantErrIs)
			}
			assert.ErrorContains(t, err, tc.wantMsg)
		})
	}
}

func TestDiscoverRoute6_NoSubnet(t *testing.T) {
	_, err := DiscoverRoute6(net.ParseIP("2001:db8:ffff::1"), "")
	assert.ErrorContains(t, err, "no interface is on the same subnet")
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
