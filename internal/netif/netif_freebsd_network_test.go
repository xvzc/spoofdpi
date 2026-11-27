//go:build network && freebsd

package netif

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/testutil"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
)

// testTunName differs from the tun-spoofdpi of a running spoofdpi.
const testTunName = "tun-netif-test"

// TestTun_RequireRoot configures a tun as TUN mode does, with a /30 on the
// broadcast-mode tun of wireguard-go and the interface up, and undoes it.
// Then it closes the tun's descriptor, which leaves the interface behind as
// a killed spoofdpi does, and destroys it.
func TestTun_RequireRoot(t *testing.T) {
	testutil.RequireRoot(t)
	dev, err := tun.CreateTUN(testTunName, 1500)
	require.NoError(t, err)
	// Close destroys the interface; it fails harmlessly once the test has.
	t.Cleanup(func() { _ = dev.Close() })

	opened, err := TunOpened(testTunName)
	require.NoError(t, err)
	assert.True(t, opened)

	require.NoError(t, AddAddr4(testTunName, testLocal, netip.Addr{}))
	require.NoError(t, SetUp(testTunName))
	assert.Contains(t, interfacePrefixes(t, testTunName), testLocal)
	assert.True(t, interfaceUp(t, testTunName))

	require.NoError(t, DelAddr4(testTunName, testLocal.Addr()))
	assert.NotContains(t, interfacePrefixes(t, testTunName), testLocal)
	assert.ErrorIs(t, DelAddr4(testTunName, testLocal.Addr()), unix.EADDRNOTAVAIL)

	require.NoError(t, SetDown(testTunName))
	assert.False(t, interfaceUp(t, testTunName))

	require.NoError(t, dev.File().Close())
	opened, err = TunOpened(testTunName)
	require.NoError(t, err)
	// Destroy blocks on a tun that is still open, so stop here if it is.
	require.False(t, opened)

	require.NoError(t, Destroy(testTunName))
	_, err = net.InterfaceByName(testTunName)
	assert.Error(t, err)
	assert.ErrorIs(t, Destroy(testTunName), unix.ENXIO)
}
