//go:build network && (darwin || freebsd || linux)

package netutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiscoverEgress_MatchesRouteTo(t *testing.T) {
	for _, fam := range []Family{FamilyV4, FamilyV6} {
		t.Run(fam.String(), func(t *testing.T) {
			path, err := RouteTo(probeDst(fam))
			if err != nil {
				t.Skipf("no route to the probe destination: %v", err)
			}

			egress, err := DiscoverEgress(fam, nil, "")
			if err != nil {
				// A loopback route is the only reason to fail here.
				require.ErrorIs(t, err, noRouteError(fam))
				t.Skipf("route is not an egress: %v", err)
			}
			assert.Equal(t, path.Iface.Index, egress.Route.Iface.Index)
			assert.Equal(t, path.Iface.Index, egress.Link.Index)
			t.Logf(
				"%s egress: iface=%s class=%s link=%s reason=%q",
				fam, egress.Route.Iface.Name, egress.Class, egress.Link.Kind,
				egress.Reason,
			)
		})
	}
}
