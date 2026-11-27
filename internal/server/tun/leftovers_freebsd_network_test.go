//go:build network && freebsd

package tun

import (
	"net"
	"net/netip"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/netif"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/route"
	"github.com/xvzc/spoofdpi/internal/server"
	"github.com/xvzc/spoofdpi/internal/testutil"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
)

// testLeftoverTun differs from the tun-spoofdpi of a running spoofdpi.
const testLeftoverTun = "tun-s5-test"

// leftoverTestFIB returns the FIB the tests write to: the last one. It
// skips the test on a host with one FIB, when that FIB has a default route
// or a tagged route, which the test could take for its own or remove, and
// while tun-spoofdpi exists, as a spoofdpi may be using that FIB.
func leftoverTestFIB(t *testing.T) int {
	t.Helper()
	if _, err := net.InterfaceByName(tunIfName); err == nil {
		t.Skipf("%s exists: a spoofdpi may be running", tunIfName)
	}
	fibs, err := unix.SysctlUint32("net.fibs")
	if err != nil {
		t.Skipf("net.fibs: %v", err)
	}
	if fibs < 2 {
		t.Skip("needs a second FIB: set net.fibs in /boot/loader.conf")
	}
	fib := int(fibs) - 1
	for _, fam := range []netutil.Family{netutil.FamilyV4, netutil.FamilyV6} {
		routes, err := route.DumpRoutes(fam, fib)
		require.NoError(t, err)
		for _, r := range routes {
			if r.Dst.Bits() == 0 || isTaggedRoute(r) {
				t.Skipf("FIB %d is not free for the test: it has the route %s", fib, r)
			}
		}
	}
	return fib
}

// TestCleanLeftovers_ConfiguredFIB_RequireRoot adds the FIB routes of the
// jobs, with lo0 as the physical interface, and a foreign route of the same
// shape, then cleans up the FIB as freebsd-fib: only the jobs' routes go.
func TestCleanLeftovers_ConfiguredFIB_RequireRoot(t *testing.T) {
	testutil.RequireRoot(t)
	fib := leftoverTestFIB(t)
	lo, err := net.InterfaceByName("lo0")
	require.NoError(t, err)

	info := &tunNetworkInfoFreeBSD{
		FIBID:             fib,
		Gateway:           netip.Addr{},
		PhysIfaceName:     lo.Name,
		PhysIfaceIndex:    lo.Index,
		PhysIfaceSubnet:   netip.MustParsePrefix("192.0.2.0/24"),
		PhysIfaceP2P:      false,
		FIBHasSubnetRoute: false,
		TUNName:           testLeftoverTun,
		TUNIndex:          0,
		TunAddr:           netip.MustParsePrefix("10.200.0.1/30"),
		RouteTargets:      mainFIBTargetsV4,
		IPv6Enabled:       false,
		HasIPv6Egress:     false,
	}
	// Each route added is deleted at the end whatever happens; one that the
	// cleanup removed fails to delete harmlessly. A route that failed to add
	// is not deleted, as it may be someone else's.
	addTestRoute := func(r route.TableRoute) {
		require.NoError(t, route.AddRoute(fib, r), "add %s", r)
		t.Cleanup(func() { _ = route.DeleteRoute(fib, r) })
	}
	var added []route.TableRoute
	for _, job := range buildJobs(info) {
		add, ok := job.Apply.(routeAddAction)
		if !ok || add.FIB != fib {
			continue
		}
		addTestRoute(add.Route)
		added = append(added, add.Route)
	}
	require.Len(t, added, 2, "the FIB subnet and default routes")
	foreign := route.TableRoute{
		Dst:         netip.MustParsePrefix("198.51.100.0/24"),
		GatewayLink: lo.Index,
	}
	addTestRoute(foreign)

	env := systemLeftoverEnv()
	env.tunName = testLeftoverTun
	server.RemoveLeftovers(zerolog.Nop(), env.find(zerolog.Nop(), fib))

	routes, err := route.DumpRoutes(netutil.FamilyV4, fib)
	require.NoError(t, err)
	for _, r := range added {
		assert.NotContains(t, routeDsts(routes), r.Dst)
	}
	assert.Contains(t, routeDsts(routes), foreign.Dst)
}

// TestCleanLeftovers_ClosedTun_RequireRoot closes the descriptor of a tun,
// which leaves the interface behind as a killed spoofdpi does, and checks
// that the cleanup destroys it, and only once it is closed.
func TestCleanLeftovers_ClosedTun_RequireRoot(t *testing.T) {
	testutil.RequireRoot(t)
	dev, err := tun.CreateTUN(testLeftoverTun, 1500)
	require.NoError(t, err)
	// Close destroys the interface; it fails harmlessly once the test has.
	t.Cleanup(func() { _ = dev.Close() })

	env := systemLeftoverEnv()
	env.tunName = testLeftoverTun
	// Only the main FIB: the routes of other FIBs are not the test's.
	env.fibCount = func() (int, error) { return 1, nil }

	assert.Empty(t, env.find(zerolog.Nop(), 0), "an open tun is a running spoofdpi")

	require.NoError(t, dev.File().Close())
	server.RemoveLeftovers(zerolog.Nop(), env.find(zerolog.Nop(), 0))

	_, err = net.InterfaceByName(testLeftoverTun)
	assert.Error(t, err, "the closed tun is destroyed")
	_, err = netif.TunOpened(testLeftoverTun)
	assert.ErrorIs(t, err, unix.ENXIO)
}

func routeDsts(routes []route.TableRoute) []netip.Prefix {
	dsts := make([]netip.Prefix, 0, len(routes))
	for _, r := range routes {
		dsts = append(dsts, r.Dst)
	}
	return dsts
}
