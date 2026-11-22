package netutil

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIPsFromAddrs(t *testing.T) {
	got := IPsFromAddrs([]netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("2001:db8::1"),
	})

	assert.Equal(t, []net.IP{
		net.ParseIP("192.0.2.1").To4(),
		net.ParseIP("2001:db8::1"),
	}, got)
	assert.Empty(t, IPsFromAddrs(nil))
}
