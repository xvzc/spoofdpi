//go:build network && darwin

package route

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/testutil"
	"golang.org/x/sys/unix"
)

// rtsockTestFIB returns the FIB the routing socket tests write to. darwin
// has only one table.
func rtsockTestFIB(*testing.T) int { return 0 }

// TestAddDeleteRoute_Scoped_RequireRoot adds a tagged route scoped to lo0
// via 127.0.0.1, as `route add -ifscope lo0 -net 192.0.2.0/24 127.0.0.1`
// does, and deletes it.
func TestAddDeleteRoute_Scoped_RequireRoot(t *testing.T) {
	testutil.RequireRoot(t)
	lo, err := net.InterfaceByName("lo0")
	require.NoError(t, err)

	r := TableRoute{
		Dst:     netip.MustParsePrefix("192.0.2.0/24"),
		Gateway: netip.MustParseAddr("127.0.0.1"),
		Index:   lo.Index,
		Flags:   unix.RTF_PROTO2 | unix.RTF_IFSCOPE,
	}
	testAddDeleteRoute(t, netutil.FamilyV4, 0, r)
}
