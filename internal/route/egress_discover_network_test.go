//go:build network && (darwin || freebsd || linux)

package route

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/netutil"
)

func TestDiscoverEgress_MatchesLookup(t *testing.T) {
	for _, fam := range []netutil.Family{netutil.FamilyV4, netutil.FamilyV6} {
		t.Run(fam.String(), func(t *testing.T) {
			path, err := Lookup(probeDst(fam))
			if err != nil {
				t.Skipf("no route to the probe destination: %v", err)
			}

			egress, err := DiscoverEgress(fam)
			if err != nil {
				// A loopback route is the only reason to fail here.
				require.ErrorIs(t, err, noRouteError(fam))
				t.Skipf("route is not an egress: %v", err)
			}
			assert.Equal(t, path.Iface.Index, egress.Route.Iface.Index)
			t.Logf("%s egress: iface=%s", fam, egress.Route.Iface.Name)
		})
	}
}
