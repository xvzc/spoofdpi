//go:build network && linux

package route

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/testutil"
)

// The tests below change the host's rules, routes and links. They use a
// preference, a table, protocol tags and a link name that nothing else is
// expected to use, refuse to run when any of them is taken, and remove
// what they add even when they fail.
const (
	testRulePref      uint32 = 27183
	testTable         uint32 = 0x7e570001
	testProtocol      uint8  = 249
	testOtherProtocol uint8  = 248
	testLinkName             = "spdtest0"
)

// skipWithoutIPv6 skips the test when the host has no IPv6 or has it
// disabled.
func skipWithoutIPv6(t *testing.T) {
	t.Helper()
	b, err := os.ReadFile("/proc/sys/net/ipv6/conf/all/disable_ipv6")
	if err != nil {
		t.Skipf("no IPv6: %v", err)
	}
	if strings.TrimSpace(string(b)) == "1" {
		t.Skip("IPv6 is disabled")
	}
}

// skipIfIPv6Refused skips the test when err is the kernel refusing IPv6:
// EAFNOSUPPORT without IPv6 support, EACCES with IPv6 disabled on a link.
func skipIfIPv6Refused(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EACCES) {
		t.Skipf("IPv6 unavailable: %v", err)
	}
}

// isTestRule reports whether r is a rule that these tests add.
func isTestRule(r Rule) bool {
	return r.Priority == testRulePref &&
		(r.Protocol == testProtocol || r.Protocol == testOtherProtocol)
}

// rulesAt returns the rules of fam with preference pref.
func rulesAt(t *testing.T, fam netutil.Family, pref uint32) []Rule {
	t.Helper()
	rules, err := Rules(fam)
	skipIfIPv6Refused(t, err)
	require.NoError(t, err)
	return slices.DeleteFunc(rules, func(r Rule) bool { return r.Priority != pref })
}

// deleteTestRules deletes the rules of fam that these tests add, one at a
// time as a fresh dump shows them, and reports any that stay.
func deleteTestRules(t *testing.T, fam netutil.Family) {
	t.Helper()
	for range 16 {
		rules, err := Rules(fam)
		if err != nil {
			t.Errorf("cleanup: %v", err)
			return
		}
		i := slices.IndexFunc(rules, isTestRule)
		if i < 0 {
			return
		}
		if err := DeleteRule(rules[i]); err != nil && !IsNotExist(err) {
			t.Errorf("cleanup: %v", err)
			return
		}
	}
	t.Errorf("cleanup: test rules of %s stay", fam)
}

// cleanupTestRules deletes the rules of fam that these tests add when the
// test ends, in case the test failed before it did.
func cleanupTestRules(t *testing.T, fam netutil.Family) {
	t.Cleanup(func() { deleteTestRules(t, fam) })
}

// routesIn returns the routes of fam in table.
func routesIn(t *testing.T, fam netutil.Family, table uint32) []RouteEntry {
	t.Helper()
	routes, err := Routes(fam)
	skipIfIPv6Refused(t, err)
	require.NoError(t, err)
	return slices.DeleteFunc(routes, func(r RouteEntry) bool { return r.Table != table })
}

// cleanupRoute deletes r when the test ends, in case the test failed
// before it did. A route that is already gone is fine.
func cleanupRoute(t *testing.T, r RouteEntry) {
	t.Cleanup(func() {
		if err := DeleteRoute(r); err != nil && !IsNotExist(err) {
			t.Errorf("cleanup: %v", err)
		}
	})
}

// requireRuleProtocol skips the test when the kernel drops rule tags.
func requireRuleProtocol(t *testing.T) {
	t.Helper()
	supported, err := RuleProtocolSupported()
	require.NoError(t, err)
	if !supported {
		t.Skip("the kernel does not keep FRA_PROTOCOL (Linux before 4.17)")
	}
}

// taggedTestRule returns r at testRulePref, looking up a table, with
// testProtocol.
func taggedTestRule(r Rule) Rule {
	r.Priority = testRulePref
	r.Action = RuleActionToTable
	r.Protocol, r.HasProtocol = testProtocol, true
	return r
}

func TestRuleModify_RequireRoot(t *testing.T) {
	testutil.RequireRoot(t)
	requireRuleProtocol(t)

	tcs := []struct {
		name string
		rule Rule
	}{
		{
			name: "ipv4 lookup main suppress_prefixlength 0",
			rule: taggedTestRule(Rule{
				Family:               netutil.FamilyV4,
				Table:                254,
				HasSuppressPrefixlen: true,
			}),
		},
		{
			name: "ipv4 from a host lookup main",
			rule: taggedTestRule(Rule{
				Family: netutil.FamilyV4,
				Table:  254,
				Src:    netip.MustParsePrefix("192.0.2.1/32"),
			}),
		},
		{
			name: "ipv4 fwmark 0/0xffffffff lookup a 32-bit table",
			rule: taggedTestRule(Rule{
				Family:    netutil.FamilyV4,
				Table:     testTable,
				Fwmask:    0xffffffff,
				HasFwmask: true,
			}),
		},
		{
			name: "ipv6 lookup main suppress_prefixlength 0",
			rule: taggedTestRule(Rule{
				Family:               netutil.FamilyV6,
				Table:                254,
				HasSuppressPrefixlen: true,
			}),
		},
		{
			name: "ipv6 fwmark 0/0xffffffff lookup a 32-bit table",
			rule: taggedTestRule(Rule{
				Family:    netutil.FamilyV6,
				Table:     testTable,
				Fwmask:    0xffffffff,
				HasFwmask: true,
			}),
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.rule
			if r.Family == netutil.FamilyV6 {
				skipWithoutIPv6(t)
			}
			require.Empty(t, rulesAt(t, r.Family, testRulePref),
				"preference %d is taken", testRulePref)
			cleanupTestRules(t, r.Family)

			err := AddRule(r)
			skipIfIPv6Refused(t, err)
			require.NoError(t, err)
			require.ErrorIs(t, AddRule(r), syscall.EEXIST)

			// A rule of the same shape with another tag, which the
			// delete must leave alone.
			twin := r
			twin.Protocol = testOtherProtocol
			err = AddRule(twin)
			hasTwin := err == nil
			if !hasTwin {
				require.ErrorIs(t, err, syscall.EEXIST)
				t.Log("the kernel takes rules that differ only in their tag as the same")
			}

			got := rulesAt(t, r.Family, testRulePref)
			for _, g := range got {
				t.Logf("dumped: %s", g)
			}
			want := []Rule{r}
			if hasTwin {
				want = append(want, twin)
			}
			assert.ElementsMatch(t, want, got)
			assert.False(t, RuleDeleteAmbiguous(r, got))

			require.NoError(t, DeleteRule(r))
			assert.ElementsMatch(t, want[1:], rulesAt(t, r.Family, testRulePref))
			err = DeleteRule(r)
			require.ErrorIs(t, err, syscall.ENOENT)
			assert.True(t, IsNotExist(err))

			if hasTwin {
				require.NoError(t, DeleteRule(twin))
			}
			assert.Empty(t, rulesAt(t, r.Family, testRulePref), "left behind")
		})
	}
}

// TestRuleDeleteFilter_RequireRoot adds a tagged rule and a twin that
// differs in one attribute the kernel's delete may take as a wildcard,
// deletes the rule, and checks that the kernel removed the rule that
// ruleDeleteMatches predicts: the first match in dump order. The twin goes
// first when the kernel takes it, so that a wildcard shows.
func TestRuleDeleteFilter_RequireRoot(t *testing.T) {
	testutil.RequireRoot(t)
	requireRuleProtocol(t)

	base := taggedTestRule(Rule{
		Family:    netutil.FamilyV4,
		Table:     testTable,
		Fwmask:    0xffffffff,
		HasFwmask: true,
	})
	with := func(edit func(r *Rule)) Rule {
		r := base
		edit(&r)
		return r
	}
	marked := with(func(r *Rule) { r.Fwmark, r.HasFwmark = 0x1, true })
	fromHost := with(func(r *Rule) { r.Src = netip.MustParsePrefix("192.0.2.1/32") })
	inverted := with(func(r *Rule) { r.Invert = true })
	otherTag := with(func(r *Rule) { r.Protocol = testOtherProtocol })

	tcs := []struct {
		name   string
		target Rule
		twin   Rule
	}{
		{name: "mark 0 and a marked twin", target: base, twin: marked},
		{name: "mark 1 and an unmarked twin", target: marked, twin: base},
		{name: "no source and a twin from a host", target: base, twin: fromHost},
		{name: "a source and a twin from all", target: fromHost, twin: base},
		{name: "an inverted twin", target: base, twin: inverted},
		// DeleteRule's safety rests on the kernel comparing the tag.
		{name: "a twin with another tag", target: base, twin: otherTag},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			fam := tc.target.Family
			require.Empty(t, rulesAt(t, fam, testRulePref),
				"preference %d is taken", testRulePref)
			cleanupTestRules(t, fam)

			order, ok := addRulePair(t, tc.twin, tc.target)
			if !ok {
				order, ok = addRulePair(t, tc.target, tc.twin)
			}
			if !ok {
				t.Logf("outcome: the kernel takes %s and %s as the same rule",
					tc.target, tc.twin)
				return
			}

			dump := rulesAt(t, fam, testRulePref)
			for _, r := range dump {
				t.Logf("dumped: %s", r)
			}
			require.Len(t, dump, 2)
			i := slices.IndexFunc(dump, func(r Rule) bool { return rulesEqual(r, tc.target) })
			require.GreaterOrEqual(t, i, 0, "target %s not in the dump", tc.target)
			target := dump[i]
			predicted := dump[slices.IndexFunc(dump, func(r Rule) bool {
				return ruleDeleteMatches(target, r)
			})]
			ambiguous := RuleDeleteAmbiguous(target, dump)

			require.NoError(t, DeleteRule(target))
			after := rulesAt(t, fam, testRulePref)
			require.Len(t, after, 1)
			deleted := dump[0]
			if rulesEqual(after[0], dump[0]) {
				deleted = dump[1]
			}
			hitTwin := !rulesEqual(deleted, target)
			t.Logf("outcome: added %s; ambiguous=%v; the delete removed the %s",
				order, ambiguous, map[bool]string{true: "twin", false: "target"}[hitTwin])
			switch {
			case rulesEqual(predicted, deleted):
			case !hitTwin:
				// Safe: the helper over-reports ambiguity.
				t.Logf("the kernel compares more than ruleDeleteMatches "+
					"assumes: it deleted the target, not the predicted %s", predicted)
			default:
				t.Errorf("predicted the delete of %s, the kernel deleted %s",
					predicted, deleted)
			}
			if hitTwin {
				assert.True(t, ambiguous, "the delete hit the twin")
			}

			deleteTestRules(t, fam)
			assert.Empty(t, rulesAt(t, fam, testRulePref), "left behind")
		})
	}
}

// addRulePair adds first and then second. It reports false, with neither
// rule left, when the kernel refuses second as a duplicate of first.
func addRulePair(t *testing.T, first, second Rule) (order string, ok bool) {
	t.Helper()
	require.NoError(t, AddRule(first))
	err := AddRule(second)
	if errors.Is(err, syscall.EEXIST) {
		deleteTestRules(t, first.Family)
		return "", false
	}
	require.NoError(t, err)
	return first.String() + " then " + second.String(), true
}

// addDummyLink creates a dummy link named testLinkName with ip and deletes
// it when the test ends. It skips the test when ip or the dummy driver is
// missing.
func addDummyLink(t *testing.T) *net.Interface {
	t.Helper()
	if _, err := net.InterfaceByName(testLinkName); err == nil {
		t.Fatalf("link %s exists", testLinkName)
	}
	bin, err := exec.LookPath("ip")
	if err != nil {
		t.Skip("ip not found")
	}
	out, err := exec.Command(bin, "link", "add", testLinkName, "type", "dummy").
		CombinedOutput()
	if err != nil {
		t.Skipf("ip link add %s type dummy: %v: %s", testLinkName, err, out)
	}
	t.Cleanup(func() {
		out, err := exec.Command(bin, "link", "del", testLinkName).CombinedOutput()
		if err != nil {
			t.Errorf("cleanup: ip link del %s: %v: %s", testLinkName, err, out)
		}
	})
	link, err := net.InterfaceByName(testLinkName)
	require.NoError(t, err)
	return link
}

// linkFlags returns the flags of the link with index.
func linkFlags(t *testing.T, index int) net.Flags {
	t.Helper()
	link, err := net.InterfaceByIndex(index)
	require.NoError(t, err)
	return link.Flags
}

// linkHasAddr reports whether the link with index has addr.
func linkHasAddr(t *testing.T, index int, addr netip.Addr) bool {
	t.Helper()
	link, err := net.InterfaceByIndex(index)
	require.NoError(t, err)
	addrs, err := link.Addrs()
	require.NoError(t, err)
	return slices.ContainsFunc(addrs, func(a net.Addr) bool {
		ipnet, ok := a.(*net.IPNet)
		return ok && ipnet.IP.Equal(addr.AsSlice())
	})
}

func TestLinkAddrRouteModify_RequireRoot(t *testing.T) {
	testutil.RequireRoot(t)
	link := addDummyLink(t)

	require.NoError(t, SetLinkUp(link.Index))
	assert.NotZero(t, linkFlags(t, link.Index)&net.FlagUp, "up")
	assert.True(t, IsNotExist(SetLinkUp(1<<30)), "a missing link")

	t.Run("address with peer", func(t *testing.T) {
		a := InterfaceAddr{
			Index:     link.Index,
			Local:     netip.MustParseAddr("192.0.2.1"),
			Peer:      netip.MustParseAddr("192.0.2.2"),
			PrefixLen: 32,
		}
		require.NoError(t, AddAddress(a))
		t.Cleanup(func() { _ = DeleteAddress(a) })
		require.ErrorIs(t, AddAddress(a), syscall.EEXIST)
		assert.True(t, linkHasAddr(t, link.Index, a.Local))

		require.NoError(t, DeleteAddress(a))
		assert.False(t, linkHasAddr(t, link.Index, a.Local), "left behind")
		assert.True(t, IsNotExist(DeleteAddress(a)), "a missing address")
	})

	routes := []RouteEntry{
		{
			Table:    testTable,
			Dst:      netip.MustParsePrefix("0.0.0.0/0"),
			Oif:      link.Index,
			Protocol: testProtocol,
			Scope:    RouteScopeLink,
			Type:     RouteTypeUnicast,
		},
		{
			Table:    testTable,
			Dst:      netip.MustParsePrefix("2000::/3"),
			Oif:      link.Index,
			Metric:   1024,
			Protocol: testProtocol,
			Scope:    RouteScopeUniverse,
			Type:     RouteTypeUnicast,
		},
	}
	for _, r := range routes {
		t.Run("route "+r.Dst.String(), func(t *testing.T) {
			fam := familyOf(r.Dst.Addr())
			if fam == netutil.FamilyV6 {
				skipWithoutIPv6(t)
			}
			require.Empty(t, routesIn(t, fam, testTable), "table %d is taken", testTable)

			err := AddRoute(r)
			skipIfIPv6Refused(t, err)
			require.NoError(t, err)
			cleanupRoute(t, r)
			require.ErrorIs(t, AddRoute(r), syscall.EEXIST)

			got := routesIn(t, fam, testTable)
			require.Len(t, got, 1)
			t.Logf("dumped: %s", got[0])
			if fam == netutil.FamilyV4 {
				assert.Empty(t, got[0].OtherAttrs)
			}
			want := r
			want.OtherAttrs = got[0].OtherAttrs
			assert.Equal(t, want, got[0])
			assert.False(t, RouteDeleteAmbiguous(got[0], got))

			require.NoError(t, DeleteRoute(got[0]))
			err = DeleteRoute(got[0])
			require.ErrorIs(t, err, syscall.ESRCH)
			assert.True(t, IsNotExist(err))
			assert.Empty(t, routesIn(t, fam, testTable), "left behind")
		})
	}

	require.NoError(t, SetLinkDown(link.Index))
	assert.Zero(t, linkFlags(t, link.Index)&net.FlagUp, "down")
}

// isTestRoute reports whether r is a route that these tests add.
func isTestRoute(r RouteEntry) bool {
	return r.Table == testTable &&
		(r.Protocol == testProtocol || r.Protocol == testOtherProtocol)
}

// deleteTestRoutes deletes the routes of fam that these tests add, one at
// a time as a fresh dump shows them, and reports any that stay.
func deleteTestRoutes(t *testing.T, fam netutil.Family) {
	t.Helper()
	for range 16 {
		routes, err := Routes(fam)
		if err != nil {
			t.Errorf("cleanup: %v", err)
			return
		}
		i := slices.IndexFunc(routes, isTestRoute)
		if i < 0 {
			return
		}
		if err := DeleteRoute(routes[i]); err != nil && !IsNotExist(err) {
			t.Errorf("cleanup: %v", err)
			return
		}
	}
	t.Errorf("cleanup: test routes of %s stay", fam)
}

// addRoutePair adds first and then second. It reports false, with neither
// route left, when the kernel refuses second as a duplicate of first.
func addRoutePair(t *testing.T, first, second RouteEntry) (order string, ok bool) {
	t.Helper()
	err := AddRoute(first)
	skipIfIPv6Refused(t, err)
	require.NoError(t, err)
	err = AddRoute(second)
	if errors.Is(err, syscall.EEXIST) {
		deleteTestRoutes(t, familyOf(first.Dst.Addr()))
		return "", false
	}
	require.NoError(t, err)
	return first.String() + " then " + second.String(), true
}

// TestRouteDeleteFilter_RequireRoot adds a tagged route and a twin that
// differs in one field, deletes the route, and checks that the kernel
// removed the route that routeDeleteMatches predicts: the first match in
// dump order. The twin goes first when the kernel takes it, so that a
// wildcard shows.
func TestRouteDeleteFilter_RequireRoot(t *testing.T) {
	testutil.RequireRoot(t)
	link := addDummyLink(t)
	require.NoError(t, SetLinkUp(link.Index))

	base4 := RouteEntry{
		Table:    testTable,
		Dst:      netip.MustParsePrefix("0.0.0.0/0"),
		Oif:      link.Index,
		Protocol: testProtocol,
		Scope:    RouteScopeLink,
		Type:     RouteTypeUnicast,
	}
	base6 := RouteEntry{
		Table:    testTable,
		Dst:      netip.MustParsePrefix("2000::/3"),
		Oif:      link.Index,
		Metric:   1024,
		Protocol: testProtocol,
		Type:     RouteTypeUnicast,
	}
	with := func(r RouteEntry, edit func(r *RouteEntry)) RouteEntry {
		edit(&r)
		return r
	}

	tcs := []struct {
		name   string
		target RouteEntry
		twin   RouteEntry
	}{
		{
			name:   "ipv4 metric 0 and a twin of metric 5",
			target: base4,
			twin:   with(base4, func(r *RouteEntry) { r.Metric = 5 }),
		},
		{
			name:   "ipv6 and a twin of another metric",
			target: base6,
			twin:   with(base6, func(r *RouteEntry) { r.Metric = 2048 }),
		},
		{
			name:   "ipv6 and a twin with another tag",
			target: base6,
			twin:   with(base6, func(r *RouteEntry) { r.Protocol = testOtherProtocol }),
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			fam := familyOf(tc.target.Dst.Addr())
			if fam == netutil.FamilyV6 {
				skipWithoutIPv6(t)
			}
			require.Empty(t, routesIn(t, fam, testTable), "table %d is taken", testTable)
			t.Cleanup(func() { deleteTestRoutes(t, fam) })

			order, ok := addRoutePair(t, tc.twin, tc.target)
			if !ok {
				order, ok = addRoutePair(t, tc.target, tc.twin)
			}
			if !ok {
				t.Logf("outcome: the kernel takes %s and %s as the same route",
					tc.target, tc.twin)
				return
			}

			dump := routesIn(t, fam, testTable)
			for _, r := range dump {
				t.Logf("dumped: %s", r)
			}
			require.Len(t, dump, 2)
			// The dump adds attributes, such as RTA_CACHEINFO, that the
			// added routes lack.
			sameAsTarget := func(r RouteEntry) bool {
				r.OtherAttrs = nil
				return routesEqual(r, tc.target)
			}
			i := slices.IndexFunc(dump, sameAsTarget)
			require.GreaterOrEqual(t, i, 0, "target %s not in the dump", tc.target)
			target := dump[i]
			predicted := dump[slices.IndexFunc(dump, func(r RouteEntry) bool {
				return routeDeleteMatches(target, r)
			})]
			ambiguous := RouteDeleteAmbiguous(target, dump)

			require.NoError(t, DeleteRoute(target))
			after := routesIn(t, fam, testTable)
			require.Len(t, after, 1)
			deleted := dump[0]
			if routesEqual(after[0], dump[0]) {
				deleted = dump[1]
			}
			hitTwin := !routesEqual(deleted, target)
			t.Logf("outcome: added %s; ambiguous=%v; the delete removed the %s",
				order, ambiguous, map[bool]string{true: "twin", false: "target"}[hitTwin])
			switch {
			case routesEqual(predicted, deleted):
			case !hitTwin:
				// Safe: the helper over-reports ambiguity.
				t.Logf("the kernel compares more than routeDeleteMatches "+
					"assumes: it deleted the target, not the predicted %s", predicted)
			default:
				t.Errorf("predicted the delete of %s, the kernel deleted %s",
					predicted, deleted)
			}
			if hitTwin {
				assert.True(t, ambiguous, "the delete hit the twin")
			}

			deleteTestRoutes(t, fam)
			assert.Empty(t, routesIn(t, fam, testTable), "left behind")
		})
	}

	require.NoError(t, SetLinkDown(link.Index))
}
