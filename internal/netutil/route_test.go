package netutil

import (
	"errors"
	"net"
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

func TestDiscoverRoute_NoIPv4Route(t *testing.T) {
	orig := discoverGateway
	t.Cleanup(func() { discoverGateway = orig })
	noGateway := errors.New("no gateway found")
	discoverGateway = func() (net.IP, error) { return nil, noGateway }

	_, err := DiscoverRoute(nil)
	require.ErrorIs(t, err, ErrNoIPv4Route)
	require.ErrorIs(t, err, noGateway)
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
