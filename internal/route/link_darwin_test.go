package route

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/netutil"
	xroute "golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func TestBSDLinkKind_Darwin(t *testing.T) {
	tcs := []struct {
		name   string
		ifType int
		p2p    bool
		want   LinkKind
	}{
		{name: "ethernet", ifType: unix.IFT_ETHER, want: LinkPhysical},
		{name: "cellular", ifType: unix.IFT_CELLULAR, want: LinkPhysical},
		{name: "bridge", ifType: unix.IFT_BRIDGE, want: LinkPhysical},
		{name: "vlan", ifType: unix.IFT_L2VLAN, want: LinkPhysical},
		{name: "lacp bond", ifType: unix.IFT_IEEE8023ADLAG, want: LinkPhysical},
		{name: "utun or ipsec", ifType: unix.IFT_OTHER, p2p: true, want: LinkVPN},
		{name: "other without p2p", ifType: unix.IFT_OTHER, want: LinkUnknown},
		{name: "ppp", ifType: unix.IFT_PPP, p2p: true, want: LinkPPP},
		{name: "gif", ifType: unix.IFT_GIF, p2p: true, want: LinkIPTunnel},
		{name: "stf", ifType: unix.IFT_STF, want: LinkIPTunnel},
		{name: "loopback", ifType: unix.IFT_LOOP, want: LinkLoopback},
		{name: "unlisted type", ifType: unix.IFT_PROPVIRTUAL, p2p: true, want: LinkUnknown},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, bsdLinkKind(tc.ifType, tc.p2p))
		})
	}
}

// TestDefaultRouteIndexes_Scoped checks that a scoped default, which a
// darwin VPN leaves for the physical interface, still counts.
func TestDefaultRouteIndexes_Scoped(t *testing.T) {
	upGw := unix.RTF_UP | unix.RTF_GATEWAY
	msgs := parseRTMFixture(t,
		dumpRoute(upGw, 20, inet4("0.0.0.0"), &xroute.LinkAddr{Index: 20}, nil),
		dumpRoute(
			upGw|unix.RTF_IFSCOPE, 4,
			inet4("0.0.0.0"), inet4("192.168.1.1"), inet4("0.0.0.0"),
		),
	)
	assert.Equal(t, []int{20, 4}, defaultRouteIndexes(msgs, netutil.FamilyV4))
}

// TestLinkInfo_Loopback reads the real interface list, which needs no
// privileges.
func TestLinkInfo_Loopback(t *testing.T) {
	ifaces, err := net.Interfaces()
	require.NoError(t, err)
	var lo *net.Interface
	for i := range ifaces {
		if ifaces[i].Flags&net.FlagLoopback != 0 {
			lo = &ifaces[i]
			break
		}
	}
	if lo == nil {
		t.Skip("no loopback interface")
	}

	link, err := linkInfo(lo.Index)
	require.NoError(t, err)
	assert.Equal(t, LinkInfo{
		Index: lo.Index, Name: lo.Name, Kind: LinkLoopback, Detail: "IFT_LOOP",
	}, link)

	_, err = linkInfo(1 << 15)
	assert.Error(t, err)
}

// TestDefaultLinks_Live reads the real routing table, which needs no
// privileges. The host may have no default route at all.
func TestDefaultLinks_Live(t *testing.T) {
	for _, fam := range []netutil.Family{netutil.FamilyV4, netutil.FamilyV6} {
		links, err := defaultLinks(fam)
		require.NoError(t, err, fam)
		for _, link := range links {
			t.Logf("%s default: %s", fam, describeLink(link))
			assert.Positive(t, link.Index)
			assert.NotEmpty(t, link.Name)
		}
	}
}
