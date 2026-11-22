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

func TestNeedsZone(t *testing.T) {
	tcs := []struct {
		ip   string
		want bool
	}{
		{"fe80::1", true},
		{"febf::1", true},
		{"2001:db8::1", false},
		{"::1", false},
		{"ff02::1", false},
		{"169.254.1.1", false},
		{"::ffff:169.254.1.1", false},
	}
	for _, tc := range tcs {
		t.Run(tc.ip, func(t *testing.T) {
			assert.Equal(t, tc.want, NeedsZone(net.ParseIP(tc.ip)))
		})
	}
}
