//go:build network && darwin

package netif

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/testutil"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
)

// testDst is the other end of the utun, next to testLocal.
var testDst = netip.MustParseAddr("198.51.100.2")

// TestUTUN_RequireRoot configures a new utun as TUN mode does, with a
// point-to-point address and the interface up, and undoes it. The utun
// goes away with its descriptor, so the cleanup only closes the device.
func TestUTUN_RequireRoot(t *testing.T) {
	testutil.RequireRoot(t)
	dev, err := tun.CreateTUN("utun", 1500)
	require.NoError(t, err)
	t.Cleanup(func() { _ = dev.Close() })
	name, err := dev.Name()
	require.NoError(t, err)

	require.NoError(t, AddAddr4(name, testLocal, testDst))
	require.NoError(t, SetUp(name))
	assert.Contains(t, interfacePrefixes(t, name), testLocal)
	assert.True(t, interfaceUp(t, name))
	flags, err := Flags(name)
	require.NoError(t, err)
	assert.NotZero(t, flags&unix.IFF_POINTOPOINT)

	require.NoError(t, DelAddr4(name, testLocal.Addr()))
	assert.NotContains(t, interfacePrefixes(t, name), testLocal)
	assert.ErrorIs(t, DelAddr4(name, testLocal.Addr()), unix.EADDRNOTAVAIL)

	require.NoError(t, SetDown(name))
	assert.False(t, interfaceUp(t, name))
}
