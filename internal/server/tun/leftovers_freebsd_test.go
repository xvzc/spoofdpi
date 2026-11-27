//go:build freebsd

package tun

import (
	"fmt"
	"net/netip"
	"slices"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/route"
	"github.com/xvzc/spoofdpi/internal/server"
	"golang.org/x/sys/unix"
)

// fakeTun is the state of tun-spoofdpi in a fakeSystem.
type fakeTun int

const (
	tunMissing fakeTun = iota
	tunClosed
	tunOpen
	// notATun is another kind of interface, whose status the tun ioctl
	// cannot read.
	notATun
	// tunStatusFails is of the tun's type, but its status cannot be read.
	tunStatusFails
)

// fakeSystem is the system a leftoverEnv of tests reads and changes.
type fakeSystem struct {
	tun       fakeTun
	fibs      int
	routes    map[int][]route.TableRoute // by FIB, both families
	deleted   []string                   // "fib N <route>" of each delete
	destroyed bool
	// openOnRecheck opens the tun between finding it and destroying it.
	openOnRecheck bool
	tunChecks     int
}

func (s *fakeSystem) env() leftoverEnv {
	return leftoverEnv{
		tunName: "tun-spoofdpi",
		tunOpened: func(string) (bool, error) {
			s.tunChecks++
			switch {
			case s.tun == tunMissing || s.destroyed:
				return false, unix.ENXIO
			case s.tun == notATun || s.tun == tunStatusFails:
				return false, unix.EINVAL
			case s.openOnRecheck && s.tunChecks > 1:
				return true, nil
			}
			return s.tun == tunOpen, nil
		},
		tunIndex: func(string) (int, bool, error) {
			if s.tun == tunMissing || s.destroyed {
				return 0, false, nil
			}
			return testTUNIndex, s.tun != notATun, nil
		},
		destroy: func(string) error {
			s.destroyed = true
			return nil
		},
		fibCount: func() (int, error) { return s.fibs, nil },
		dumpRoutes: func(fam netutil.Family, fib int) ([]route.TableRoute, error) {
			var out []route.TableRoute
			for _, r := range s.routes[fib] {
				if r.Dst.Addr().Is4() == (fam == netutil.FamilyV4) {
					out = append(out, r)
				}
			}
			return out, nil
		},
		deleteRoute: func(fib int, r route.TableRoute) error {
			i := slices.IndexFunc(s.routes[fib], func(have route.TableRoute) bool {
				return have.Dst == r.Dst && have.Gateway == r.Gateway &&
					have.GatewayLink == r.GatewayLink
			})
			if i < 0 {
				return unix.ESRCH
			}
			s.deleted = append(s.deleted, fmt.Sprintf("fib %d %s", fib, s.routes[fib][i].Dst))
			s.routes[fib] = slices.Delete(s.routes[fib], i, i+1)
			return nil
		},
	}
}

const (
	staticFlags = unix.RTF_UP | unix.RTF_STATIC
	tagFlags    = staticFlags | unix.RTF_PROTO2
)

func tunRouteOf(dst string, flags int) route.TableRoute {
	return route.TableRoute{
		Dst:         netip.MustParsePrefix(dst),
		GatewayLink: testTUNIndex,
		Index:       testTUNIndex,
		IfName:      "tun-spoofdpi",
		Flags:       flags,
	}
}

func defaultViaGateway(gateway string, flags int) route.TableRoute {
	return route.TableRoute{
		Dst:     testDefaultDst,
		Gateway: netip.MustParseAddr(gateway),
		Index:   testPhysIndex,
		IfName:  "em0",
		Flags:   flags | unix.RTF_GATEWAY,
	}
}

func subnetVia(dst string, flags int) route.TableRoute {
	return route.TableRoute{
		Dst:         netip.MustParsePrefix(dst),
		GatewayLink: testPhysIndex,
		Index:       testPhysIndex,
		IfName:      "em0",
		Flags:       flags,
	}
}

func loopbackRoute() route.TableRoute {
	return route.TableRoute{
		Dst:         netip.MustParsePrefix("127.0.0.1/32"),
		GatewayLink: 1,
		Index:       1,
		IfName:      "lo0",
		Flags:       staticFlags | unix.RTF_HOST,
	}
}

// crashedRun returns the routes that a run in fib leaves behind.
func crashedRun(fib int) map[int][]route.TableRoute {
	return map[int][]route.TableRoute{
		0: {
			tunRouteOf("0.0.0.0/1", tagFlags),
			tunRouteOf("128.0.0.0/1", tagFlags),
			tunRouteOf("2000::/3", tagFlags),
		},
		fib: {
			loopbackRoute(),
			subnetVia("192.168.1.0/24", tagFlags),
			defaultViaGateway("192.168.1.1", tagFlags),
		},
	}
}

func clean(t *testing.T, s *fakeSystem, configuredFIB int) []server.Leftover {
	t.Helper()
	leftovers := s.env().find(zerolog.Nop(), configuredFIB)
	server.RemoveLeftovers(zerolog.Nop(), leftovers)
	return leftovers
}

func TestCleanLeftovers_ClosedTunAnchor(t *testing.T) {
	s := &fakeSystem{tun: tunClosed, fibs: 4, routes: crashedRun(2)}

	clean(t, s, 2)

	assert.Equal(t, []string{
		"fib 0 0.0.0.0/1",
		"fib 0 128.0.0.0/1",
		"fib 0 2000::/3",
		"fib 2 0.0.0.0/0",
		"fib 2 192.168.1.0/24",
	}, s.deleted, "the default route goes before the subnet route")
	assert.True(t, s.destroyed)
	assert.Equal(t, []route.TableRoute{loopbackRoute()}, s.routes[2])
}

// TestCleanLeftovers_OtherFIBsWarnOnly checks that the tagged routes of a
// FIB other than the configured one stay, with one warning for the FIB
// that tells how to remove them, while the closed tun and its routes go.
func TestCleanLeftovers_OtherFIBsWarnOnly(t *testing.T) {
	routes := crashedRun(2)
	routes[3] = []route.TableRoute{defaultViaGateway("10.0.0.1", tagFlags)}
	s := &fakeSystem{tun: tunClosed, fibs: 4, routes: routes}

	leftovers := clean(t, s, 3)

	assert.Equal(t, []string{
		"fib 0 0.0.0.0/1",
		"fib 0 128.0.0.0/1",
		"fib 0 2000::/3",
		"fib 3 0.0.0.0/0",
	}, s.deleted)
	assert.Len(t, routes[2], 3, "FIB 2 is not the configured FIB")
	assert.True(t, s.destroyed)

	var warned []server.Leftover
	for _, l := range leftovers {
		if l.Remove == nil {
			warned = append(warned, l)
		}
	}
	require.Len(t, warned, 1, "one warning for FIB 2")
	assert.Contains(t, warned[0].Description, "fib 2")
	assert.Contains(t, warned[0].Description, "start spoofdpi once with --freebsd-fib 2")
	assert.Equal(t,
		"route -n delete default 192.168.1.1 -fib 2; "+
			"route -n delete -net 192.168.1.0/24 -interface em0 -fib 2",
		warned[0].ManualCommand)
}

func TestCleanLeftovers_ConfiguredFIBAnchorWithoutTun(t *testing.T) {
	routes := crashedRun(3)
	// Without the tun, the main FIB routes are not tied to anything.
	s := &fakeSystem{tun: tunMissing, fibs: 4, routes: routes}

	clean(t, s, 3)

	assert.Equal(t, []string{"fib 3 0.0.0.0/0", "fib 3 192.168.1.0/24"}, s.deleted)
	assert.Len(t, s.routes[0], 3, "main FIB routes stay without the tun")
	assert.False(t, s.destroyed)
}

// TestCleanLeftovers_OtherFIBWithoutTun checks that the tagged routes of a
// FIB other than the configured one are warned about at every start, even
// without the tun, and stay.
func TestCleanLeftovers_OtherFIBWithoutTun(t *testing.T) {
	s := &fakeSystem{tun: tunMissing, fibs: 4, routes: crashedRun(2)}

	leftovers := clean(t, s, 3)

	assert.Empty(t, s.deleted)
	require.Len(t, leftovers, 1)
	assert.Nil(t, leftovers[0].Remove)
	assert.Contains(t, leftovers[0].Description, "--freebsd-fib 2")
}

func TestCleanLeftovers_OtherFIBAbove15(t *testing.T) {
	routes := map[int][]route.TableRoute{
		16: {defaultViaGateway("10.0.0.1", tagFlags)},
	}
	s := &fakeSystem{tun: tunMissing, fibs: 17, routes: routes}

	leftovers := clean(t, s, 3)

	require.Len(t, leftovers, 1)
	assert.NotContains(t, leftovers[0].Description, "--freebsd-fib")
	assert.Contains(t, leftovers[0].Description, "remove them by hand")
	assert.Equal(
		t,
		"route -n delete default 10.0.0.1 -fib 16",
		leftovers[0].ManualCommand,
	)
	assert.Len(t, routes[16], 1)
}

func TestCleanLeftovers_LiveInstance(t *testing.T) {
	s := &fakeSystem{tun: tunOpen, fibs: 4, routes: crashedRun(3)}

	assert.Empty(t, clean(t, s, 3))
	assert.Empty(t, s.deleted)
	assert.False(t, s.destroyed)
}

func TestCleanLeftovers_NotATun(t *testing.T) {
	s := &fakeSystem{tun: notATun, fibs: 4, routes: crashedRun(3)}

	clean(t, s, 3)

	assert.Equal(t, []string{"fib 3 0.0.0.0/0", "fib 3 192.168.1.0/24"}, s.deleted,
		"no tun anchor, but the configured FIB is still cleaned up")
	assert.Len(t, s.routes[0], 3)
	assert.False(t, s.destroyed)
}

// TestCleanLeftovers_TunStatusUnknown checks that nothing goes when a tun
// does not report whether it is open: another spoofdpi may be running.
func TestCleanLeftovers_TunStatusUnknown(t *testing.T) {
	s := &fakeSystem{tun: tunStatusFails, fibs: 4, routes: crashedRun(3)}

	assert.Empty(t, clean(t, s, 3))
	assert.Empty(t, s.deleted)
	assert.False(t, s.destroyed)
}

func TestCleanLeftovers_MultipleFIBs(t *testing.T) {
	routes := crashedRun(1)
	routes[2] = []route.TableRoute{defaultViaGateway("10.0.0.1", tagFlags)}
	routes[3] = []route.TableRoute{subnetVia("10.1.0.0/16", tagFlags)}
	s := &fakeSystem{tun: tunClosed, fibs: 4, routes: routes}

	leftovers := clean(t, s, 1)

	assert.Contains(t, s.deleted, "fib 1 0.0.0.0/0")
	assert.Len(t, routes[2], 1, "only the configured FIB is cleaned up")
	assert.Len(t, routes[3], 1)
	var warnedFIBs []string
	for _, l := range leftovers {
		if l.Remove == nil {
			warnedFIBs = append(warnedFIBs, l.ManualCommand)
		}
	}
	assert.Equal(t, []string{
		"route -n delete default 10.0.0.1 -fib 2",
		"route -n delete -net 10.1.0.0/16 -interface em0 -fib 3",
	}, warnedFIBs)
}

func TestCleanLeftovers_ForeignRoutesStay(t *testing.T) {
	foreignDefault := defaultViaGateway("192.168.1.1", staticFlags)
	foreign := []route.TableRoute{
		// An untagged route of the same shape, such as one of an earlier
		// version.
		foreignDefault,
		// Tagged, but of another shape.
		{
			Dst:         netip.MustParsePrefix("2001:db8::/32"),
			GatewayLink: testPhysIndex,
			Flags:       tagFlags,
		},
		// Tagged, but made by the kernel.
		subnetVia("192.168.2.0/24", tagFlags|unix.RTF_PINNED),
		// Tagged, but rejecting.
		subnetVia("192.168.3.0/24", tagFlags|unix.RTF_REJECT),
		// Tagged, but not static.
		subnetVia("192.168.4.0/24", unix.RTF_UP|unix.RTF_PROTO2),
	}
	mainForeign := []route.TableRoute{
		// Untagged route into the tun, such as one of an earlier version.
		tunRouteOf("0.0.0.0/1", staticFlags),
		// Tagged route into another interface.
		{
			Dst:         netip.MustParsePrefix("128.0.0.0/1"),
			GatewayLink: 9,
			Flags:       tagFlags,
		},
		// Tagged route into the tun to another destination.
		tunRouteOf("10.0.0.0/8", tagFlags),
	}
	s := &fakeSystem{
		tun:  tunClosed,
		fibs: 4,
		routes: map[int][]route.TableRoute{
			0: slices.Clone(mainForeign),
			2: slices.Clone(foreign),
			3: slices.Clone(foreign),
		},
	}

	leftovers := clean(t, s, 3)

	assert.Empty(t, s.deleted)
	assert.Equal(t, mainForeign, s.routes[0])
	assert.Equal(t, foreign, s.routes[2])
	assert.Equal(t, foreign, s.routes[3])
	assert.True(t, s.destroyed)

	var warned []string
	for _, l := range leftovers {
		if l.Remove == nil {
			warned = append(warned, l.ManualCommand)
		}
	}
	assert.Equal(t, []string{
		"route -n delete -net 0.0.0.0/1 -interface tun-spoofdpi -fib 0",
		"route -n delete default 192.168.1.1 -fib 3",
	}, warned, "only lookalikes tied to an anchor are warned about; "+
		"FIB 2 is not spoofdpi's alone")
}

func TestCleanLeftovers_RechecksBeforeRemoving(t *testing.T) {
	t.Run("route changed since it was found", func(t *testing.T) {
		s := &fakeSystem{tun: tunMissing, fibs: 4, routes: crashedRun(3)}
		leftovers := s.env().find(zerolog.Nop(), 3)
		require.NotEmpty(t, leftovers)
		// Someone replaces the tagged default route with their own.
		s.routes[3][2] = defaultViaGateway("192.168.1.1", staticFlags)

		server.RemoveLeftovers(zerolog.Nop(), leftovers)

		assert.Equal(t, []string{"fib 3 192.168.1.0/24"}, s.deleted)
		assert.Contains(t, s.routes[3], defaultViaGateway("192.168.1.1", staticFlags))
	})
	t.Run("tun opened since it was found", func(t *testing.T) {
		s := &fakeSystem{tun: tunClosed, fibs: 2, openOnRecheck: true}

		clean(t, s, 0)

		assert.False(t, s.destroyed)
	})
}

func TestCleanLeftovers_DeleteKeepsOtherNexthops(t *testing.T) {
	s := &fakeSystem{tun: tunMissing, fibs: 4, routes: crashedRun(3)}
	var deletes []route.TableRoute
	env := s.env()
	deleteRoute := env.deleteRoute
	env.deleteRoute = func(fib int, r route.TableRoute) error {
		deletes = append(deletes, r)
		return deleteRoute(fib, r)
	}

	server.RemoveLeftovers(zerolog.Nop(), env.find(zerolog.Nop(), 3))

	assert.Equal(t, []route.TableRoute{
		{Dst: testDefaultDst, Gateway: netip.MustParseAddr("192.168.1.1")},
		{Dst: netip.MustParsePrefix("192.168.1.0/24"), GatewayLink: testPhysIndex},
	}, deletes, "each delete names the gateway of the route")
}

func TestCleanLeftovers_PermissionHint(t *testing.T) {
	s := &fakeSystem{tun: tunMissing, fibs: 4, routes: crashedRun(3)}
	env := s.env()
	env.deleteRoute = func(int, route.TableRoute) error {
		return fmt.Errorf("delete route: %w", unix.EPERM)
	}

	leftovers := env.find(zerolog.Nop(), 3)
	require.NotEmpty(t, leftovers)
	for _, l := range leftovers {
		err := l.Remove()
		assert.ErrorIs(t, err, unix.EPERM)
		assert.ErrorContains(t, err, "run spoofdpi as root")
	}
}

func TestCleanLeftovers_ConfiguredFIBOutOfRange(t *testing.T) {
	s := &fakeSystem{tun: tunMissing, fibs: 2, routes: crashedRun(3)}

	assert.Empty(t, clean(t, s, 3))
}

func TestLeftoversAfterReset_FreeBSD(t *testing.T) {
	routes := crashedRun(3)
	routes[0] = append(routes[0], tunRouteOf("0.0.0.0/1", staticFlags))
	routes[3] = append(routes[3], defaultViaGateway("10.0.0.1", staticFlags))
	routes[2] = []route.TableRoute{defaultViaGateway("10.0.0.1", tagFlags)}
	s := &fakeSystem{tun: tunOpen, fibs: 4, routes: routes}

	leftovers := s.env().afterReset(
		zerolog.Nop(),
		runInfo{FIB: 3, TUNName: "tun-spoofdpi", TUNIndex: testTUNIndex},
	)

	var got []string
	for _, l := range leftovers {
		got = append(got, l.ManualCommand)
	}
	assert.Equal(t, []string{
		"route -n delete -net 0.0.0.0/1 -interface tun-spoofdpi -fib 0",
		"route -n delete -net 128.0.0.0/1 -interface tun-spoofdpi -fib 0",
		"route -n delete -inet6 -net 2000::/3 -interface tun-spoofdpi -fib 0",
		"route -n delete default 192.168.1.1 -fib 3",
		"route -n delete -net 192.168.1.0/24 -interface em0 -fib 3",
	}, got, "only the tagged routes of this run's tun and FIB")
	assert.Empty(t, s.deleted)
}

func TestManualRouteDelete(t *testing.T) {
	assert.Equal(t,
		"route -n delete default -interface ppp0 -fib 2",
		manualRouteDelete(2, route.TableRoute{
			Dst:         testDefaultDst,
			GatewayLink: 4,
			IfName:      "ppp0",
		}))
	assert.Equal(t,
		"route -n delete -net 192.0.2.0/24 -fib 2",
		manualRouteDelete(2, route.TableRoute{
			Dst:         netip.MustParsePrefix("192.0.2.0/24"),
			GatewayLink: 4,
		}), "without the interface name, any route to the subnet")
}
