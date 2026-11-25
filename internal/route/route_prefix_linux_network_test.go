//go:build network && linux

package route

import (
	"net/netip"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ipRouteGetPrefix runs `ip -o route get fibmatch` for dst and returns the
// prefix of the route it reports. ok is false when ip reports no route or
// a route of another type than unicast. It skips the test when the tool is
// missing or does not know fibmatch.
func ipRouteGetPrefix(t *testing.T, dst netip.Addr) (_ netip.Prefix, ok bool) {
	t.Helper()
	bin, err := exec.LookPath("ip")
	if err != nil {
		t.Skip("ip not found")
	}
	out, err := exec.Command(bin, "-o", "route", "get", "fibmatch", dst.String()).
		CombinedOutput()
	if strings.Contains(string(out), "garbage") {
		t.Skipf("ip does not know fibmatch: %s", out)
	}
	if err != nil {
		t.Logf("ip -o route get fibmatch %s: %v: %s", dst, err, out)
		return netip.Prefix{}, false
	}

	fields := strings.Fields(string(out))
	require.NotEmpty(t, fields, "ip printed nothing")
	// ip prints the type first unless it is unicast.
	switch fields[0] {
	case "unreachable", "blackhole", "prohibit", "throw", "local", "broadcast",
		"anycast", "multicast", "nat":
		return netip.Prefix{}, false
	case "default":
		return netip.PrefixFrom(netip.IPv4Unspecified(), 0), true
	}
	if p, err := netip.ParsePrefix(fields[0]); err == nil {
		return p, true
	}
	addr, err := netip.ParseAddr(fields[0])
	require.NoError(t, err, "destination in %s", out)
	return netip.PrefixFrom(addr, addr.BitLen()), true
}

func TestRoutePrefixTo_MatchesIPRouteGet(t *testing.T) {
	dsts := []netip.Addr{probeDstV4}
	for _, r := range tunCandidateRanges {
		local := r.Addr().Next()
		dsts = append(dsts, local, local.Next())
	}

	for _, dst := range dsts {
		t.Run(dst.String(), func(t *testing.T) {
			want, ok := ipRouteGetPrefix(t, dst)
			got, err := routePrefixTo(dst)
			if !ok {
				require.ErrorIs(t, err, ErrNoIPv4Route)
				t.Skipf("ip reports no unicast route to %s", dst)
			}
			require.NoError(t, err)
			t.Logf("ip: %s; routePrefixTo: %s", want, got)
			assert.Equal(t, want, got)
		})
	}
}
