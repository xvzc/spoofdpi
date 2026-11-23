//go:build network && linux

package netutil

import (
	"net/netip"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ipRouteGetResult is what `ip -o route get` prints for one destination.
type ipRouteGetResult struct {
	dev     string
	gateway netip.Addr
	src     netip.Addr
}

// ipRouteGet runs `ip -o route get` for dst. ok is false when ip reports
// no route. It skips the test when the tool is missing.
func ipRouteGet(t *testing.T, dst netip.Addr) (res ipRouteGetResult, ok bool) {
	t.Helper()
	bin, err := exec.LookPath("ip")
	if err != nil {
		t.Skip("ip not found")
	}
	out, err := exec.Command(bin, "-o", "route", "get", dst.String()).CombinedOutput()
	if err != nil {
		t.Logf("ip -o route get %s: %v: %s", dst, err, out)
		return ipRouteGetResult{}, false
	}

	fields := strings.Fields(string(out))
	for i := 0; i+1 < len(fields); i++ {
		switch fields[i] {
		case "dev":
			res.dev = fields[i+1]
		case "via":
			res.gateway, _ = netip.ParseAddr(fields[i+1])
		case "src":
			res.src, _ = netip.ParseAddr(fields[i+1])
		}
	}
	return res, res.dev != ""
}

func TestRouteTo_MatchesIPRouteGet(t *testing.T) {
	for _, fam := range []Family{FamilyV4, FamilyV6} {
		t.Run(fam.String(), func(t *testing.T) {
			dst := probeDst(fam)
			want, ok := ipRouteGet(t, dst)
			got, err := RouteTo(dst)
			if !ok {
				noRoute := ErrNoIPv4Route
				if fam == FamilyV6 {
					noRoute = ErrNoIPv6Route
				}
				require.ErrorIs(t, err, noRoute)
				t.Skipf("ip reports no route to %s", dst)
			}
			require.NoError(t, err)
			t.Logf(
				"ip: dev=%s via=%s src=%s; RouteTo: iface=%s gateway=%s src=%s table=%d",
				want.dev, want.gateway, want.src,
				got.Iface.Name, got.Gateway, got.Src, got.Table,
			)
			assert.Equal(t, want.dev, got.Iface.Name)
			assert.Equal(t, want.gateway, got.Gateway)
			assert.Equal(t, want.src, got.Src)

			// The probe has no route of its own, so the kernel used a
			// default route, whose link defaultLinks must list.
			links, err := defaultLinks(fam)
			require.NoError(t, err)
			assert.True(t, slices.ContainsFunc(links, func(l LinkInfo) bool {
				return l.Index == got.Iface.Index
			}), "defaults %v lack %s", links, got.Iface.Name)
		})
	}
}
