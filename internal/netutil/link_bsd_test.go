//go:build darwin || freebsd

package netutil

import (
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// dumpRoute returns a routing table dump entry with flags, index and the
// addresses dst, gateway and netmask, any of which may be nil.
func dumpRoute(flags, index int, dst, gateway, netmask route.Addr) *route.RouteMessage {
	m := rtmReply(flags, index, rtmAddrs(dst, gateway, netmask, nil, nil)...)
	m.Seq = 0
	return m
}

func TestDefaultRouteIndexes(t *testing.T) {
	upGw := unix.RTF_UP | unix.RTF_GATEWAY
	gw4, gw6 := inet4("192.168.1.1"), inet6("fe80::1")
	zero4, zero6 := inet4("0.0.0.0"), inet6("::")
	utunGw := &route.LinkAddr{Index: 20}

	msgs := parseRTMFixture(t,
		// IPv4 defaults: en0, utun (interface route), en0 again.
		dumpRoute(upGw, 4, zero4, gw4, zero4),
		dumpRoute(upGw, 20, zero4, utunGw, nil),
		dumpRoute(upGw, 4, zero4, gw4, nil),
		// Not IPv4 defaults.
		dumpRoute(upGw, 5, inet4("10.0.0.0"), gw4, inet4("255.0.0.0")),
		dumpRoute(upGw, 5, zero4, gw4, inet4("255.0.0.0")),
		dumpRoute(upGw|unix.RTF_HOST, 5, zero4, gw4, nil),
		dumpRoute(upGw|unix.RTF_REJECT, 5, zero4, gw4, nil),
		dumpRoute(upGw|unix.RTF_BLACKHOLE, 5, zero4, gw4, nil),
		dumpRoute(unix.RTF_GATEWAY, 5, zero4, gw4, nil),
		dumpRoute(upGw, 0, zero4, gw4, nil),
		dumpRoute(upGw, 5, nil, gw4, nil),
		// IPv6 defaults.
		dumpRoute(upGw, 4, zero6, gw6, zero6),
		dumpRoute(upGw, 8, zero6, utunGw, nil),
	)

	assert.Equal(t, []int{4, 20}, defaultRouteIndexes(msgs, FamilyV4))
	assert.Equal(t, []int{4, 8}, defaultRouteIndexes(msgs, FamilyV6))
	assert.Empty(t, defaultRouteIndexes(msgs[3:11], FamilyV4))
}

func TestBSDLinkInfo(t *testing.T) {
	en0 := bsdLinkInfo(4, "en0", unix.IFF_UP|unix.IFF_BROADCAST, syscall.IFT_ETHER)
	assert.Equal(t, LinkInfo{
		Index: 4, Name: "en0", Kind: LinkPhysical, Detail: "IFT_ETHER",
	}, en0)

	ppp := bsdLinkInfo(9, "ppp0", unix.IFF_UP|unix.IFF_POINTOPOINT, syscall.IFT_PPP)
	assert.Equal(t, LinkInfo{
		Index: 9, Name: "ppp0", Kind: LinkPPP, Detail: "IFT_PPP p2p",
	}, ppp)

	lo := bsdLinkInfo(1, "lo0", unix.IFF_UP|unix.IFF_LOOPBACK, syscall.IFT_ETHER)
	assert.Equal(t, LinkLoopback, lo.Kind, "the loopback flag wins over the type")

	unknown := bsdLinkInfo(30, "x0", unix.IFF_UP, 0xee)
	assert.Equal(t, LinkUnknown, unknown.Kind)
	assert.Equal(t, "IFT_0xee", unknown.Detail)

	noType := bsdLinkInfo(31, "x1", unix.IFF_UP, -1)
	assert.Equal(t, LinkUnknown, noType.Kind)
	assert.Equal(t, "IFT_?", noType.Detail)
}
