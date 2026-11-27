package route

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	xroute "golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// TestRouteMessage_FreeBSDDeleteWithGateway checks that a delete keeps the
// gateway, which narrows it to the route through that gateway, and that a
// link gateway is its index alone.
func TestRouteMessage_FreeBSDDeleteWithGateway(t *testing.T) {
	m := parsedRouteMessage(t, unix.RTM_DELETE, TableRoute{
		Dst:     netip.MustParsePrefix("0.0.0.0/0"),
		Gateway: netip.MustParseAddr("192.168.1.1"),
		Flags:   unix.RTF_PROTO2,
	}, linkGateway)
	assert.Equal(t, inet4("192.168.1.1"), m.Addrs[unix.RTAX_GATEWAY])
	assert.NotZero(t, m.Flags&unix.RTF_GATEWAY)

	m = parsedRouteMessage(t, unix.RTM_DELETE, TableRoute{
		Dst:         netip.MustParsePrefix("192.168.1.0/24"),
		GatewayLink: 1,
		Flags:       unix.RTF_PROTO2,
	}, linkGateway)
	assert.Equal(t, &xroute.LinkAddr{Index: 1}, m.Addrs[unix.RTAX_GATEWAY])
	assert.Zero(t, m.Flags&unix.RTF_GATEWAY)
}
