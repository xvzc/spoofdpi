//go:build network && (darwin || freebsd)

package netutil

import (
	"net"
	"net/netip"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// routeGetPrefix runs `route -n get` for dst and returns the prefix of the
// route it reports: its destination and mask, "default" for 0.0.0.0/0, and
// the destination alone for a host route, which has no mask. ok is false
// when route reports no route. It skips the test when the tool is missing
// or fails.
func routeGetPrefix(t *testing.T, dst netip.Addr) (_ netip.Prefix, ok bool) {
	t.Helper()
	bin, err := exec.LookPath("route")
	if err != nil {
		t.Skip("route not found")
	}
	out, err := exec.Command(bin, "-n", "get", dst.String()).CombinedOutput()
	if err != nil {
		t.Skipf("route -n get %s: %v: %s", dst, err, out)
	}
	// route exits with 0 even when the kernel has no route.
	if strings.Contains(string(out), "not in table") {
		return netip.Prefix{}, false
	}

	var destination, mask string
	for line := range strings.Lines(string(out)) {
		key, value, found := strings.Cut(strings.TrimSpace(line), ":")
		if !found {
			continue
		}
		value = strings.TrimSpace(value)
		if value == "default" {
			value = "0.0.0.0"
		}
		switch key {
		case "destination":
			destination = value
		case "mask":
			mask = value
		}
	}
	addr, err := netip.ParseAddr(destination)
	require.NoError(t, err, "destination in %s", out)
	if mask == "" {
		return netip.PrefixFrom(addr, addr.BitLen()), true
	}
	m, err := netip.ParseAddr(mask)
	require.NoError(t, err, "mask in %s", out)
	ones, _ := net.IPMask(m.AsSlice()).Size()
	return netip.PrefixFrom(addr, ones), true
}

func TestRoutePrefixTo_MatchesRouteCommand(t *testing.T) {
	dsts := []netip.Addr{
		probeDstV4,
		netip.MustParseAddr("127.0.0.1"),
		netip.MustParseAddr("169.254.1.1"),
	}
	add := func(a netip.Addr) {
		if !slices.Contains(dsts, a) {
			dsts = append(dsts, a)
		}
	}
	for _, r := range tunCandidateRanges {
		local := r.Addr().Next()
		add(local)
		add(local.Next())
	}
	if cidr, err := FindSafeCIDR(); err == nil {
		local := netip.MustParsePrefix(cidr).Addr().Next()
		add(local)
		add(local.Next())
	}
	// The neighbors of the interface addresses take the routes of their
	// networks, such as a LAN's or a VPN's.
	addrs, err := net.InterfaceAddrs()
	require.NoError(t, err)
	for _, n := range interfaceNetsV4(addrs) {
		if !n.Addr().IsLoopback() {
			add(n.Addr().Next())
		}
	}

	for _, dst := range dsts {
		t.Run(dst.String(), func(t *testing.T) {
			want, ok := routeGetPrefix(t, dst)
			got, err := routePrefixTo(dst)
			if !ok {
				require.ErrorIs(t, err, ErrNoIPv4Route)
				t.Skipf("route reports no route to %s", dst)
			}
			require.NoError(t, err)
			t.Logf("route: %s; routePrefixTo: %s", want, got)
			assert.Equal(t, want, got)
		})
	}
}

// TestFindSafeCIDR_Live checks the subnet FindSafeCIDR picks on this host
// against `route -n get`: both host addresses take a route no more
// specific than the probe's.
func TestFindSafeCIDR_Live(t *testing.T) {
	probe, ok := routeGetPrefix(t, probeDstV4)
	if !ok {
		t.Skipf("route reports no route to %s", probeDstV4)
	}
	cidr, err := FindSafeCIDR()
	require.NoError(t, err)
	t.Logf("FindSafeCIDR: %s; probe route: %s", cidr, probe)

	local := netip.MustParsePrefix(cidr).Addr().Next()
	for _, h := range []netip.Addr{local, local.Next()} {
		p, ok := routeGetPrefix(t, h)
		require.True(t, ok, "route reports no route to %s", h)
		assert.LessOrEqual(t, p.Bits(), probe.Bits(), "route to %s is %s", h, p)
	}
}
