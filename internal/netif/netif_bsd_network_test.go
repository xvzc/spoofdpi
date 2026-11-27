//go:build network && (darwin || freebsd)

package netif

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// testLocal is in TEST-NET-2 (RFC 5737), which no host routes.
var testLocal = netip.MustParsePrefix("198.51.100.1/30")

// interfacePrefixes returns the IPv4 addresses of the interface name with
// their netmasks, as the standard library reads them.
func interfacePrefixes(t *testing.T, name string) []netip.Prefix {
	t.Helper()
	iface, err := net.InterfaceByName(name)
	require.NoError(t, err)
	addrs, err := iface.Addrs()
	require.NoError(t, err)

	var prefixes []netip.Prefix
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok || ipNet.IP.To4() == nil {
			continue
		}
		addr, _ := netip.AddrFromSlice(ipNet.IP.To4())
		ones, _ := ipNet.Mask.Size()
		prefixes = append(prefixes, netip.PrefixFrom(addr, ones))
	}
	return prefixes
}

// interfaceUp reports whether the standard library sees name as up.
func interfaceUp(t *testing.T, name string) bool {
	t.Helper()
	iface, err := net.InterfaceByName(name)
	require.NoError(t, err)
	return iface.Flags&net.FlagUp != 0
}

func TestFlags_Loopback(t *testing.T) {
	flags, err := Flags("lo0")
	require.NoError(t, err)

	assert.NotZero(t, flags&unix.IFF_UP)
	assert.NotZero(t, flags&unix.IFF_LOOPBACK)
}

func TestFlags_NoSuchInterface(t *testing.T) {
	_, err := Flags("spoofdpi-none0")

	assert.ErrorIs(t, err, unix.ENXIO)
}
