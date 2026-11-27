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

// fakeLinks makes the link lookup return the given answers.
func fakeLinks(t *testing.T, infos map[int]LinkInfo, infoErr error) {
	t.Helper()
	orig := linkInfoOf
	t.Cleanup(func() { linkInfoOf = orig })
	linkInfoOf = func(index int) (LinkInfo, error) {
		if infoErr != nil {
			return LinkInfo{}, infoErr
		}
		return infos[index], nil
	}
}

func TestEgressOf(t *testing.T) {
	en0 := LinkInfo{Index: 4, Name: "en0", Kind: LinkPhysical, Detail: "IFT_ETHER"}
	utun := LinkInfo{Index: 20, Name: "utun4", Kind: LinkVPN, Detail: "IFT_OTHER p2p"}
	ppp := LinkInfo{Index: 8, Name: "ppp0", Kind: LinkPPP, Detail: "ARPHRD_PPP"}
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
		name    string
		fam     netutil.Family
		link    LinkInfo
		infoErr error
		wantErr error
	}{
		{name: "physical", fam: netutil.FamilyV4, link: en0},
		{name: "vpn", fam: netutil.FamilyV4, link: utun},
		{name: "ppp", fam: netutil.FamilyV4, link: ppp},
		{name: "unknown link", fam: netutil.FamilyV4, link: unk},
		{
			name:    "unreadable link",
			fam:     netutil.FamilyV4,
			link:    en0,
			infoErr: errors.New("boom"),
		},
		{
			name:    "loopback is no IPv4 route",
			fam:     netutil.FamilyV4,
			link:    lo,
			wantErr: ErrNoIPv4,
		},
		{
			name:    "loopback is no IPv6 route",
			fam:     netutil.FamilyV6,
			link:    lo,
			wantErr: ErrNoIPv6,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			fakeLinks(t, map[int]LinkInfo{tc.link.Index: tc.link}, tc.infoErr)

			egress, err := egressOf(pathOn(tc.fam, tc.link))
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				assert.ErrorContains(t, err, "goes through loopback lo0")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.link.Index, egress.Route.Iface.Index)
			assert.Equal(t, "192.168.1.1", egress.Route.Gateway.String())
			assert.Equal(t, "192.168.1.11", egress.Route.LocalIP.String())
		})
	}
}

func TestDiscoverEgress_KernelRoute(t *testing.T) {
	en0 := net.Interface{Index: 4, Name: "en0", Flags: net.FlagUp}
	link := LinkInfo{Index: 4, Name: "en0", Kind: LinkPhysical, Detail: "IFT_ETHER"}
	fakeDiscovery(t, kernelRoute{
		ifIndex: 4,
		gateway: netip.MustParseAddr("192.168.1.1"),
		src:     netip.MustParseAddr("192.168.1.11"),
	}, nil, en0, nil)
	fakeLinks(t, map[int]LinkInfo{4: link}, nil)

	egress, err := DiscoverEgress(netutil.FamilyV4)
	require.NoError(t, err)
	assert.Equal(t, "en0", egress.Route.Iface.Name)
	assert.Equal(t, "192.168.1.1", egress.Route.Gateway.String())
}

func TestDiscoverEgress_NoKernelRoute(t *testing.T) {
	en0 := net.Interface{Index: 4, Name: "en0", Flags: net.FlagUp}
	fakeDiscovery(t, kernelRoute{}, errNoRoute(probeDstV6), en0, nil)
	fakeLinks(t, nil, nil)

	_, err := DiscoverEgress(netutil.FamilyV6)
	assert.ErrorIs(t, err, ErrNoIPv6)
}

func TestDiscoverEgress_Errors(t *testing.T) {
	en0 := net.Interface{Index: 4, Name: "en0", Flags: net.FlagUp}

	t.Run("lookup errors are returned", func(t *testing.T) {
		fakeDiscovery(t, kernelRoute{}, errors.New("netlink down"), en0, nil)
		fakeLinks(t, nil, nil)

		_, err := DiscoverEgress(netutil.FamilyV6)
		assert.ErrorContains(t, err, "netlink down")
	})

	t.Run("loopback kernel route is an error", func(t *testing.T) {
		lo := net.Interface{Index: 1, Name: "lo0", Flags: net.FlagUp | net.FlagLoopback}
		fakeDiscovery(t, kernelRoute{ifIndex: 1}, nil, lo, nil)
		fakeLinks(t, map[int]LinkInfo{
			1: {Index: 1, Name: "lo0", Kind: LinkLoopback},
		}, nil)

		_, err := DiscoverEgress(netutil.FamilyV6)
		assert.ErrorIs(t, err, ErrNoIPv6)
	})
}
