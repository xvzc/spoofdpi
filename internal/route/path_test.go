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

// fakeRouteTo replaces the kernel lookup and the interface lookup of
// Lookup for one test. ifaces maps interface indexes to interfaces.
func fakeRouteTo(
	t *testing.T,
	lookup func(netip.Addr) (kernelRoute, error),
	ifaces map[int]net.Interface,
) {
	t.Helper()
	origRoute, origIface := osRouteTo, interfaceByIndex
	t.Cleanup(func() { osRouteTo, interfaceByIndex = origRoute, origIface })
	osRouteTo = lookup
	interfaceByIndex = func(index int) (*net.Interface, error) {
		iface, ok := ifaces[index]
		if !ok {
			return nil, errors.New("no such interface")
		}
		return &iface, nil
	}
}

func TestProbeDst(t *testing.T) {
	assert.Equal(t, netip.MustParseAddr("192.0.2.1"), probeDst(netutil.FamilyV4))
	assert.Equal(t, netip.MustParseAddr("2001:db8::1"), probeDst(netutil.FamilyV6))
}

func TestLookup(t *testing.T) {
	en0 := net.Interface{Index: 4, Name: "en0", Flags: net.FlagUp}
	wg0 := net.Interface{Index: 7, Name: "wg0", Flags: net.FlagUp}
	ifaces := map[int]net.Interface{4: en0, 7: wg0}

	tcs := []struct {
		name string
		dst  string
		kr   kernelRoute
		want Path
	}{
		{
			name: "ipv4 via gateway",
			dst:  "192.0.2.1",
			kr: kernelRoute{
				ifIndex: 4,
				gateway: netip.MustParseAddr("192.168.1.1"),
				src:     netip.MustParseAddr("192.168.1.11"),
				table:   254,
			},
			want: Path{
				Family:  netutil.FamilyV4,
				Dst:     netip.MustParseAddr("192.0.2.1"),
				Iface:   en0,
				Gateway: netip.MustParseAddr("192.168.1.1"),
				Src:     netip.MustParseAddr("192.168.1.11"),
				Table:   254,
			},
		},
		{
			name: "interface route has no gateway",
			dst:  "192.0.2.1",
			kr:   kernelRoute{ifIndex: 7, table: 51820},
			want: Path{
				Family: netutil.FamilyV4,
				Dst:    netip.MustParseAddr("192.0.2.1"),
				Iface:  wg0,
				Table:  51820,
			},
		},
		{
			name: "unspecified gateway is no gateway",
			dst:  "192.0.2.1",
			kr:   kernelRoute{ifIndex: 7, gateway: netip.IPv4Unspecified()},
			want: Path{
				Family: netutil.FamilyV4,
				Dst:    netip.MustParseAddr("192.0.2.1"),
				Iface:  wg0,
			},
		},
		{
			name: "ipv6 link-local gateway gets the interface as zone",
			dst:  "2001:db8::1",
			kr: kernelRoute{
				ifIndex: 4,
				gateway: netip.MustParseAddr("fe80::1%4"),
				src:     netip.MustParseAddr("2001:db8:1::2"),
			},
			want: Path{
				Family:  netutil.FamilyV6,
				Dst:     netip.MustParseAddr("2001:db8::1"),
				Iface:   en0,
				Gateway: netip.MustParseAddr("fe80::1"),
				Zone:    "en0",
				Src:     netip.MustParseAddr("2001:db8:1::2"),
			},
		},
		{
			name: "ipv6 global gateway has no zone",
			dst:  "2001:db8::1",
			kr: kernelRoute{
				ifIndex: 4,
				gateway: netip.MustParseAddr("2001:db8:1::1"),
			},
			want: Path{
				Family:  netutil.FamilyV6,
				Dst:     netip.MustParseAddr("2001:db8::1"),
				Iface:   en0,
				Gateway: netip.MustParseAddr("2001:db8:1::1"),
			},
		},
		{
			name: "ipv4-mapped destination is looked up as ipv4",
			dst:  "::ffff:192.0.2.1",
			kr: kernelRoute{
				ifIndex: 4,
				gateway: netip.MustParseAddr("::ffff:192.168.1.1"),
			},
			want: Path{
				Family:  netutil.FamilyV4,
				Dst:     netip.MustParseAddr("192.0.2.1"),
				Iface:   en0,
				Gateway: netip.MustParseAddr("192.168.1.1"),
			},
		},
		{
			name: "ipv4 link-local destination needs no zone",
			dst:  "169.254.1.1",
			kr:   kernelRoute{ifIndex: 4},
			want: Path{
				Family: netutil.FamilyV4,
				Dst:    netip.MustParseAddr("169.254.1.1"),
				Iface:  en0,
			},
		},
		{
			name: "source of the other family is dropped",
			dst:  "192.0.2.1",
			kr: kernelRoute{
				ifIndex: 4,
				src:     netip.MustParseAddr("2001:db8:1::2"),
			},
			want: Path{
				Family: netutil.FamilyV4,
				Dst:    netip.MustParseAddr("192.0.2.1"),
				Iface:  en0,
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			var asked netip.Addr
			fakeRouteTo(t, func(dst netip.Addr) (kernelRoute, error) {
				asked = dst
				return tc.kr, nil
			}, ifaces)

			got, err := Lookup(netip.MustParseAddr(tc.dst))
			require.NoError(t, err)
			assert.Equal(t, tc.want, *got)
			assert.Equal(t, tc.want.Dst, asked)
		})
	}
}

func TestLookup_Errors(t *testing.T) {
	en0 := net.Interface{Index: 4, Name: "en0"}
	ifaces := map[int]net.Interface{4: en0}
	kernelErr := errors.New("kernel says no")

	tcs := []struct {
		name    string
		dst     netip.Addr
		kr      kernelRoute
		lookErr error
		wantIs  error
		wantMsg string
	}{
		{
			name:    "invalid destination",
			dst:     netip.Addr{},
			wantMsg: "invalid destination",
		},
		{
			name:    "zoned destination",
			dst:     netip.MustParseAddr("fe80::1%en0"),
			wantMsg: "zoned destinations are not supported",
		},
		{
			name:    "ipv6 link-local destination without zone",
			dst:     netip.MustParseAddr("fe80::1"),
			wantMsg: "link-local destinations need a zone",
		},
		{
			name:    "ipv6 multicast destination",
			dst:     netip.MustParseAddr("ff02::1"),
			wantMsg: "multicast destinations are not supported",
		},
		{
			name:    "ipv4 multicast destination",
			dst:     netip.MustParseAddr("224.0.0.1"),
			wantMsg: "multicast destinations are not supported",
		},
		{
			name:    "kernel error is passed through",
			dst:     netip.MustParseAddr("192.0.2.1"),
			lookErr: kernelErr,
			wantIs:  kernelErr,
		},
		{
			name:    "unknown output interface",
			dst:     netip.MustParseAddr("192.0.2.1"),
			kr:      kernelRoute{ifIndex: 99},
			wantMsg: "output interface 99",
		},
		{
			name: "gateway of the other family",
			dst:  netip.MustParseAddr("192.0.2.1"),
			kr: kernelRoute{
				ifIndex: 4,
				gateway: netip.MustParseAddr("fe80::1"),
			},
			wantMsg: "other address family",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			fakeRouteTo(t, func(netip.Addr) (kernelRoute, error) {
				return tc.kr, tc.lookErr
			}, ifaces)

			_, err := Lookup(tc.dst)
			require.Error(t, err)
			if tc.wantIs != nil {
				assert.ErrorIs(t, err, tc.wantIs)
			}
			if tc.wantMsg != "" {
				assert.Contains(t, err.Error(), tc.wantMsg)
			}
		})
	}
}

func TestErrNoRoute(t *testing.T) {
	err := errNoRoute(netip.MustParseAddr("192.0.2.1"))
	assert.ErrorIs(t, err, ErrNoIPv4)
	assert.NotErrorIs(t, err, ErrNoIPv6)
	assert.Contains(t, err.Error(), "192.0.2.1")

	err = errNoRoute(netip.MustParseAddr("2001:db8::1"))
	assert.ErrorIs(t, err, ErrNoIPv6)
	assert.NotErrorIs(t, err, ErrNoIPv4)
}

func TestPath_Route(t *testing.T) {
	en0 := net.Interface{Index: 4, Name: "en0"}

	t.Run("with gateway and source", func(t *testing.T) {
		p := Path{
			Family:  netutil.FamilyV6,
			Iface:   en0,
			Gateway: netip.MustParseAddr("fe80::1"),
			Zone:    "en0",
			Src:     netip.MustParseAddr("2001:db8:1::2"),
		}
		r := p.Route()
		assert.Equal(t, netutil.FamilyV6, r.Family)
		assert.Equal(t, en0, r.Iface)
		assert.Equal(t, net.ParseIP("fe80::1"), r.Gateway)
		assert.Equal(t, net.ParseIP("2001:db8:1::2"), r.LocalIP)
		assert.Equal(t, "fe80::1%en0", r.GatewayString())
	})

	t.Run("interface route", func(t *testing.T) {
		p := Path{Family: netutil.FamilyV4, Iface: en0}
		r := p.Route()
		assert.Nil(t, r.Gateway)
		assert.Nil(t, r.LocalIP)
		assert.Empty(t, r.Zone)
	})

	t.Run("ipv4 addresses are 4 bytes", func(t *testing.T) {
		p := Path{
			Family:  netutil.FamilyV4,
			Iface:   en0,
			Gateway: netip.MustParseAddr("192.168.1.1"),
			Src:     netip.MustParseAddr("192.168.1.11"),
		}
		r := p.Route()
		assert.Equal(t, net.IP{192, 168, 1, 1}, r.Gateway)
		assert.Equal(t, net.IP{192, 168, 1, 11}, r.LocalIP)
	})
}
