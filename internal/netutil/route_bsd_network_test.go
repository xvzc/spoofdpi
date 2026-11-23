//go:build network && (darwin || freebsd)

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

// routeGetResult is what `route -n get` prints for one destination.
type routeGetResult struct {
	iface string
	// gateway is the zero Addr when route prints no IP gateway or the
	// route lacks the GATEWAY flag.
	gateway netip.Addr
}

// routeGet runs `route -n get` with args. ok is false when route reports
// no route. It skips the test when the tool is missing or fails.
func routeGet(t *testing.T, args ...string) (res routeGetResult, ok bool) {
	t.Helper()
	bin, err := exec.LookPath("route")
	if err != nil {
		t.Skip("route not found")
	}
	out, err := exec.Command(bin, append([]string{"-n", "get"}, args...)...).
		CombinedOutput()
	if err != nil {
		t.Skipf("route -n get %s: %v: %s", strings.Join(args, " "), err, out)
	}

	// route exits with 0 even when the kernel has no route.
	if strings.Contains(string(out), "not in table") {
		return routeGetResult{}, false
	}

	var gateway string
	var hasGatewayFlag bool
	for line := range strings.Lines(string(out)) {
		key, value, found := strings.Cut(strings.TrimSpace(line), ":")
		if !found {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "interface":
			res.iface = value
		case "gateway":
			gateway = value
		case "flags":
			hasGatewayFlag = strings.Contains(value, "GATEWAY")
		}
	}
	if addr, err := netip.ParseAddr(gateway); err == nil && hasGatewayFlag {
		res.gateway = addr.WithZone("")
	}
	return res, res.iface != ""
}

func TestRouteTo_MatchesRouteCommand(t *testing.T) {
	tcs := []struct {
		name string
		fam  Family
		args []string
	}{
		{name: "ipv4", fam: FamilyV4, args: []string{probeDst(FamilyV4).String()}},
		{
			name: "ipv6",
			fam:  FamilyV6,
			args: []string{"-inet6", probeDst(FamilyV6).String()},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			want, ok := routeGet(t, tc.args...)
			got, err := RouteTo(probeDst(tc.fam))
			if !ok {
				noRoute := ErrNoIPv4Route
				if tc.fam == FamilyV6 {
					noRoute = ErrNoIPv6Route
				}
				require.ErrorIs(t, err, noRoute)
				t.Skipf("route reports no route to %s", probeDst(tc.fam))
			}
			require.NoError(t, err)
			t.Logf(
				"route: iface=%s gateway=%s; RouteTo: iface=%s gateway=%s src=%s",
				want.iface, want.gateway, got.Iface.Name, got.Gateway, got.Src,
			)
			assert.Equal(t, want.iface, got.Iface.Name)
			assert.Equal(t, want.gateway, got.Gateway)

			// The probe has no route of its own, so the kernel used a
			// default route, whose link defaultLinks must list.
			links, err := defaultLinks(tc.fam)
			require.NoError(t, err)
			assert.True(t, slices.ContainsFunc(links, func(l LinkInfo) bool {
				return l.Index == got.Iface.Index
			}), "defaults %v lack %s", links, got.Iface.Name)
		})
	}
}

func TestPrimaryInterface_MatchesRouteCommand(t *testing.T) {
	want, ok := routeGet(t, "default")
	got, skipped, err := PrimaryInterface()
	if !ok {
		require.ErrorIs(t, err, ErrNoIPv4Route)
		t.Skip("route reports no default route")
	}
	require.NoError(t, err)
	if skipped != nil {
		// A VPN holds the primary default; route reports its interface.
		t.Logf(
			"route: iface=%s; PrimaryInterface: %s, skipped %s",
			want.iface, got.Name, describeLink(*skipped),
		)
		assert.Equal(t, want.iface, skipped.Name)
		assert.NotEqual(t, want.iface, got.Name)
		return
	}
	t.Logf("route: iface=%s; PrimaryInterface: %s", want.iface, got.Name)
	assert.Equal(t, want.iface, got.Name)
}
