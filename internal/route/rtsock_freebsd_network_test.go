//go:build network && freebsd

package route

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/testutil"
	"golang.org/x/sys/unix"
)

// rtsockTestFIB returns the FIB the routing socket tests write to: the
// last one, so that a route a test leaves behind stays out of FIB 0. It
// skips the test on a host with one FIB.
func rtsockTestFIB(t *testing.T) int {
	t.Helper()
	fibs, err := unix.SysctlUint32("net.fibs")
	if err != nil {
		t.Skipf("net.fibs: %v", err)
	}
	if fibs < 2 {
		t.Skip("needs a second FIB: set net.fibs in /boot/loader.conf")
	}
	return int(fibs) - 1
}

// TestAddRoute_OtherFIB_RequireRoot checks that a route added to the test
// FIB stays out of FIB 0.
func TestAddRoute_OtherFIB_RequireRoot(t *testing.T) {
	testutil.RequireRoot(t)
	fib := rtsockTestFIB(t)
	lo, err := net.InterfaceByName("lo0")
	require.NoError(t, err)

	r := TableRoute{
		Dst:         netip.MustParsePrefix("192.0.2.124/32"),
		GatewayLink: lo.Index,
		Flags:       unix.RTF_PROTO2,
	}
	addTestRoute(t, fib, r)
	_, ok := findTableRoute(t, netutil.FamilyV4, fib, r.Dst)
	assert.True(t, ok, "%s is not in fib %d", r.Dst, fib)
	_, ok = findTableRoute(t, netutil.FamilyV4, 0, r.Dst)
	assert.False(t, ok, "%s is in fib 0", r.Dst)
}
