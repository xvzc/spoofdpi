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

// fakeLinks makes the link and default-route lookups return the given
// answers.
func fakeLinks(
	t *testing.T,
	infos map[int]LinkInfo,
	infoErr error,
	defaults []LinkInfo,
	defaultsErr error,
) (defaultsCalls *int) {
	t.Helper()
	origInfo, origDefaults := linkInfoOf, defaultLinksOf
	t.Cleanup(func() { linkInfoOf, defaultLinksOf = origInfo, origDefaults })
	linkInfoOf = func(index int) (LinkInfo, error) {
		if infoErr != nil {
			return LinkInfo{}, infoErr
		}
		return infos[index], nil
	}
	calls := 0
	defaultLinksOf = func(netutil.Family) ([]LinkInfo, error) {
		calls++
		return defaults, defaultsErr
	}
	return &calls
}

// fakeKernelRoute makes the kernel route lookup return answer.
func fakeKernelRoute(t *testing.T, answer func(dst netip.Addr) (kernelRoute, error)) {
	t.Helper()
	orig := osRouteTo
	t.Cleanup(func() { osRouteTo = orig })
	osRouteTo = answer
}

func TestClassifyPath(t *testing.T) {
	en0 := LinkInfo{Index: 4, Name: "en0", Kind: LinkPhysical, Detail: "IFT_ETHER"}
	en1 := LinkInfo{Index: 5, Name: "en1", Kind: LinkPhysical, Detail: "IFT_ETHER"}
	utun := LinkInfo{Index: 20, Name: "utun4", Kind: LinkVPN, Detail: "IFT_OTHER p2p"}
	ppp := LinkInfo{Index: 8, Name: "ppp0", Kind: LinkPPP, Detail: "ARPHRD_PPP"}
	sit := LinkInfo{Index: 9, Name: "sit1", Kind: LinkIPTunnel, Detail: "kind=sit"}
	unk := LinkInfo{Index: 10, Name: "x0", Kind: LinkUnknown, Detail: "kind=dummy"}
	lo := LinkInfo{Index: 1, Name: "lo0", Kind: LinkLoopback, Detail: "IFT_LOOP"}

	pathOn := func(fam netutil.Family, link LinkInfo) *Path {
		return &Path{
			Family:  fam,
			Dst:     probeDst(fam),
			Iface:   net.Interface{Index: link.Index, Name: link.Name},
			Gateway: netip.MustParseAddr("192.168.1.1"),
			Src:     netip.MustParseAddr("192.168.1.11"),
		}
	}

	tcs := []struct {
		name         string
		fam          netutil.Family
		link         LinkInfo
		infoErr      error
		defaults     []LinkInfo
		defaultsErr  error
		wantClass    EgressClass
		wantKind     LinkKind
		wantDetail   string
		wantReason   string
		wantDefaults int
		wantErr      error
	}{
		{
			name:       "physical is direct without reading default routes",
			fam:        netutil.FamilyV4,
			link:       en0,
			defaults:   []LinkInfo{en0, en1},
			wantClass:  EgressDirect,
			wantKind:   LinkPhysical,
			wantDetail: "IFT_ETHER",
		},
		{
			name:      "vpn is a vpn without reading default routes",
			fam:       netutil.FamilyV4,
			link:      utun,
			wantClass: EgressVPN,
			wantKind:  LinkVPN,
		},
		{
			name:         "ppp next to a physical default is a vpn",
			fam:          netutil.FamilyV4,
			link:         ppp,
			defaults:     []LinkInfo{ppp, en0},
			wantClass:    EgressVPN,
			wantKind:     LinkPPP,
			wantDefaults: 1,
		},
		{
			name:         "ppp alone is an uplink",
			fam:          netutil.FamilyV4,
			link:         ppp,
			defaults:     []LinkInfo{ppp},
			wantClass:    EgressUplink,
			wantKind:     LinkPPP,
			wantDefaults: 1,
		},
		{
			name:         "ip tunnel alone is an uplink",
			fam:          netutil.FamilyV6,
			link:         sit,
			defaults:     []LinkInfo{sit},
			wantClass:    EgressUplink,
			wantKind:     LinkIPTunnel,
			wantDefaults: 1,
		},
		{
			name:         "unknown link is unknown",
			fam:          netutil.FamilyV4,
			link:         unk,
			wantClass:    EgressUnknown,
			wantKind:     LinkUnknown,
			wantDefaults: 1,
		},
		{
			name:         "unreadable link is unknown",
			fam:          netutil.FamilyV4,
			link:         en0,
			infoErr:      errors.New("boom"),
			wantClass:    EgressUnknown,
			wantKind:     LinkUnknown,
			wantDetail:   "link unreadable: boom",
			wantDefaults: 1,
		},
		{
			name:         "unreadable default routes are noted in the reason",
			fam:          netutil.FamilyV4,
			link:         ppp,
			defaultsErr:  errors.New("denied"),
			wantClass:    EgressUplink,
			wantKind:     LinkPPP,
			wantReason:   " (default routes unreadable: denied)",
			wantDefaults: 1,
		},
		{
			name:    "loopback is no IPv4 route",
			fam:     netutil.FamilyV4,
			link:    lo,
			wantErr: ErrNoIPv4Route,
		},
		{
			name:    "loopback is no IPv6 route",
			fam:     netutil.FamilyV6,
			link:    lo,
			wantErr: ErrNoIPv6Route,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			calls := fakeLinks(
				t,
				map[int]LinkInfo{tc.link.Index: tc.link},
				tc.infoErr,
				tc.defaults,
				tc.defaultsErr,
			)

			egress, err := ClassifyPath(pathOn(tc.fam, tc.link))
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				assert.ErrorContains(t, err, "goes through loopback lo0")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantClass, egress.Class)
			assert.Equal(t, tc.wantKind, egress.Link.Kind)
			if tc.wantDetail != "" {
				assert.Equal(t, tc.wantDetail, egress.Link.Detail)
			}
			assert.Contains(t, egress.Reason, tc.wantReason)
			assert.Equal(t, tc.wantDefaults, *calls)
			assert.Equal(t, tc.link.Index, egress.Route.Iface.Index)
			assert.Equal(t, "192.168.1.1", egress.Route.Gateway.String())
			assert.Equal(t, "192.168.1.11", egress.Route.LocalIP.String())
		})
	}
}

func TestDiscoverEgress_NoGateway(t *testing.T) {
	en0 := net.Interface{Index: 4, Name: "en0", Flags: net.FlagUp}
	link := LinkInfo{Index: 4, Name: "en0", Kind: LinkPhysical, Detail: "IFT_ETHER"}
	fakeDiscovery(t, kernelRoute{
		ifIndex: 4,
		gateway: netip.MustParseAddr("192.168.1.1"),
		src:     netip.MustParseAddr("192.168.1.11"),
	}, nil, en0, nil)
	fakeLinks(t, map[int]LinkInfo{4: link}, nil, nil, nil)

	egress, err := DiscoverEgress(netutil.FamilyV4, nil, "")
	require.NoError(t, err)
	assert.Equal(t, EgressDirect, egress.Class)
	assert.Equal(t, "en0", egress.Route.Iface.Name)
	assert.Equal(t, "192.168.1.1", egress.Route.Gateway.String())
}

func TestDiscoverEgress_NoKernelRoute(t *testing.T) {
	en0 := net.Interface{Index: 4, Name: "en0", Flags: net.FlagUp}
	fakeDiscovery(t, kernelRoute{}, errNoRoute(probeDstV6), en0, nil)
	fakeLinks(t, nil, nil, nil, nil)

	_, err := DiscoverEgress(netutil.FamilyV6, nil, "")
	assert.ErrorIs(t, err, ErrNoIPv6Route)
}

func TestDiscoverEgress_Gateway(t *testing.T) {
	en0 := net.Interface{Index: 4, Name: "en0", Flags: net.FlagUp}
	utun := net.Interface{Index: 20, Name: "utun4", Flags: net.FlagUp}
	en0Link := LinkInfo{Index: 4, Name: "en0", Kind: LinkPhysical, Detail: "IFT_ETHER"}
	utunLink := LinkInfo{Index: 20, Name: "utun4", Kind: LinkVPN, Detail: "IFT_OTHER p2p"}
	gateway := net.ParseIP("fe80::1")

	t.Run("full-tunnel vpn overrides the gateway", func(t *testing.T) {
		fakeZoneInterfaces(t, en0, utun)
		fakeKernelRoute(t, func(netip.Addr) (kernelRoute, error) {
			return kernelRoute{ifIndex: 20}, nil
		})
		fakeLinks(t, map[int]LinkInfo{4: en0Link, 20: utunLink}, nil, nil, nil)

		egress, err := DiscoverEgress(netutil.FamilyV6, gateway, "en0")
		require.NoError(t, err)
		assert.Equal(t, EgressVPN, egress.Class)
		assert.Equal(t, "utun4", egress.Link.Name)
		assert.Equal(t, "en0", egress.Route.Iface.Name)
		assert.Equal(t, "fe80::1%en0", egress.Route.GatewayString())
	})

	t.Run("no kernel route classifies the gateway's interface", func(t *testing.T) {
		fakeZoneInterfaces(t, en0, utun)
		fakeKernelRoute(t, func(dst netip.Addr) (kernelRoute, error) {
			return kernelRoute{}, errNoRoute(dst)
		})
		fakeLinks(t, map[int]LinkInfo{4: en0Link, 20: utunLink}, nil, nil, nil)

		egress, err := DiscoverEgress(netutil.FamilyV6, gateway, "en0")
		require.NoError(t, err)
		assert.Equal(t, EgressDirect, egress.Class)
		assert.Equal(t, "en0", egress.Link.Name)
		assert.Equal(t, "fe80::1%en0", egress.Route.GatewayString())
	})

	t.Run("other lookup errors are returned", func(t *testing.T) {
		fakeZoneInterfaces(t, en0)
		fakeKernelRoute(t, func(netip.Addr) (kernelRoute, error) {
			return kernelRoute{}, errors.New("netlink down")
		})
		fakeLinks(t, nil, nil, nil, nil)

		_, err := DiscoverEgress(netutil.FamilyV6, gateway, "en0")
		assert.ErrorContains(t, err, "netlink down")
		assert.NotErrorIs(t, err, ErrBadGateway)
	})

	t.Run("loopback kernel route is an error", func(t *testing.T) {
		lo := net.Interface{Index: 1, Name: "lo0", Flags: net.FlagUp | net.FlagLoopback}
		fakeZoneInterfaces(t, en0, lo)
		fakeKernelRoute(t, func(netip.Addr) (kernelRoute, error) {
			return kernelRoute{ifIndex: 1}, nil
		})
		fakeLinks(t, map[int]LinkInfo{
			1: {Index: 1, Name: "lo0", Kind: LinkLoopback},
		}, nil, nil, nil)

		_, err := DiscoverEgress(netutil.FamilyV6, gateway, "en0")
		assert.ErrorIs(t, err, ErrNoIPv6Route)
	})

	t.Run("gateway errors name the gateway", func(t *testing.T) {
		fakeZoneInterfaces(t, en0)
		fakeLinks(t, nil, nil, nil, nil)

		_, err := DiscoverEgress(netutil.FamilyV6, gateway, "nosuch")
		assert.EqualError(t, err,
			`gateway fe80::1: zone "nosuch": no such network interface`)
		assert.ErrorIs(t, err, ErrBadGateway)

		_, err = DiscoverEgress(netutil.FamilyV4, net.ParseIP("2001:db8::1"), "")
		assert.ErrorContains(t, err, "is not an IPv4 address")
		assert.ErrorIs(t, err, ErrBadGateway)
	})
}
