//go:build network && (darwin || freebsd)

package route

import (
	"errors"
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/testutil"
	"golang.org/x/sys/unix"
)

// findTableRoute returns the route to dst in the table of fam and fib, and
// whether there is one.
func findTableRoute(
	t *testing.T,
	fam netutil.Family,
	fib int,
	dst netip.Prefix,
) (TableRoute, bool) {
	t.Helper()
	routes, err := DumpRoutes(fam, fib)
	require.NoError(t, err)
	i := slices.IndexFunc(routes, func(r TableRoute) bool { return r.Dst == dst })
	if i < 0 {
		return TableRoute{}, false
	}
	return routes[i], true
}

// addTestRoute adds r to fib and deletes it when the test ends, even when
// it fails.
func addTestRoute(t *testing.T, fib int, r TableRoute) {
	t.Helper()
	require.NoError(t, AddRoute(fib, r))
	t.Cleanup(func() {
		if err := DeleteRoute(fib, r); err != nil && !errors.Is(err, unix.ESRCH) {
			t.Errorf("clean up: %v", err)
		}
	})
}

// testAddDeleteRoute adds r, a tagged route of fam, to fib, finds it in the
// dump, deletes it, and checks that it is gone.
func testAddDeleteRoute(t *testing.T, fam netutil.Family, fib int, r TableRoute) {
	t.Helper()
	_, exists := findTableRoute(t, fam, fib, r.Dst)
	require.False(t, exists, "%s is in the table before the test", r.Dst)

	addTestRoute(t, fib, r)
	assert.ErrorIs(t, AddRoute(fib, r), unix.EEXIST)

	got, ok := findTableRoute(t, fam, fib, r.Dst)
	require.True(t, ok, "%s is not in the dump", r.Dst)
	t.Logf("dumped: %s", got)
	want := unix.RTF_UP | unix.RTF_STATIC | unix.RTF_PROTO2
	assert.Equal(t, want, got.Flags&want, "flags %#x", got.Flags)
	assert.Equal(t, r.Gateway, got.Gateway)
	assert.Equal(t, r.GatewayLink, got.GatewayLink)
	assert.Equal(t, r.Gateway.IsValid(), got.Flags&unix.RTF_GATEWAY != 0)
	assert.Equal(t, r.Dst.IsSingleIP(), got.Flags&unix.RTF_HOST != 0)

	require.NoError(t, DeleteRoute(fib, r))
	_, ok = findTableRoute(t, fam, fib, r.Dst)
	assert.False(t, ok, "%s is still in the table", r.Dst)
	assert.ErrorIs(t, DeleteRoute(fib, r), unix.ESRCH)
}

func TestAddDeleteRoute_RequireRoot(t *testing.T) {
	testutil.RequireRoot(t)
	fib := rtsockTestFIB(t)
	lo, err := net.InterfaceByName("lo0")
	require.NoError(t, err)

	tcs := []struct {
		name string
		fam  netutil.Family
		r    TableRoute
	}{
		{
			name: "ipv4 host route via interface",
			fam:  netutil.FamilyV4,
			r: TableRoute{
				Dst:         netip.MustParsePrefix("192.0.2.123/32"),
				GatewayLink: lo.Index,
				Flags:       unix.RTF_PROTO2,
			},
		},
		{
			name: "ipv4 network route via interface",
			fam:  netutil.FamilyV4,
			r: TableRoute{
				Dst:         netip.MustParsePrefix("198.51.100.0/24"),
				GatewayLink: lo.Index,
				Flags:       unix.RTF_PROTO2,
			},
		},
		{
			name: "ipv6 network route via interface",
			fam:  netutil.FamilyV6,
			r: TableRoute{
				Dst:         netip.MustParsePrefix("2001:db8:5d::/64"),
				GatewayLink: lo.Index,
				Flags:       unix.RTF_PROTO2,
			},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			testAddDeleteRoute(t, tc.fam, fib, tc.r)
		})
	}
}
