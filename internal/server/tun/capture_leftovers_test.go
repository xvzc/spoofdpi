package tun

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/route"
)

// fakeNetlink is a captureNetlink over rules and routes in memory. A delete
// removes the first entry equal to its argument, as the kernel does when
// the delete is not ambiguous, which the code under test checks first.
type fakeNetlink struct {
	tunIndex      int
	tunPersistent bool
	addrs         map[int][]netip.Addr
	rules         map[netutil.Family][]route.Rule
	routes        map[netutil.Family][]route.RouteEntry
	// deleteErr, when set, fails every delete.
	deleteErr error
	// beforeDelete, when set, runs before each delete is decided: on the
	// dump that precedes it.
	beforeDelete func(*fakeNetlink)
	dumps        int
}

func newFakeNetlink(rules []route.Rule, routes []route.RouteEntry) *fakeNetlink {
	f := &fakeNetlink{
		rules:  make(map[netutil.Family][]route.Rule),
		routes: make(map[netutil.Family][]route.RouteEntry),
	}
	for _, r := range rules {
		f.rules[r.Family] = append(f.rules[r.Family], r)
	}
	for _, fam := range captureFamilies {
		slices.SortStableFunc(f.rules[fam], func(a, b route.Rule) int {
			return int(int64(a.Priority) - int64(b.Priority))
		})
	}
	for _, e := range routes {
		fam := netutil.FamilyV4
		if e.Dst.Addr().Is6() {
			fam = netutil.FamilyV6
		}
		f.routes[fam] = append(f.routes[fam], e)
	}
	return f
}

func (f *fakeNetlink) TUNIndex() (int, error) {
	if f.dumps++; f.dumps > 1 && f.beforeDelete != nil {
		f.beforeDelete(f)
	}
	return f.tunIndex, nil
}

func (f *fakeNetlink) TUNPersistent() (bool, error) {
	return f.tunPersistent, nil
}

func (f *fakeNetlink) InterfaceAddrs() (map[int][]netip.Addr, error) {
	return f.addrs, nil
}

func (f *fakeNetlink) Rules(fam netutil.Family) ([]route.Rule, error) {
	return slices.Clone(f.rules[fam]), nil
}

func (f *fakeNetlink) Routes(fam netutil.Family) ([]route.RouteEntry, error) {
	return slices.Clone(f.routes[fam]), nil
}

func (f *fakeNetlink) DeleteRule(r route.Rule) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	i := slices.IndexFunc(f.rules[r.Family], func(x route.Rule) bool {
		return reflect.DeepEqual(x, r)
	})
	if i < 0 {
		return syscall.ENOENT
	}
	f.rules[r.Family] = slices.Delete(f.rules[r.Family], i, i+1)
	return nil
}

func (f *fakeNetlink) DeleteRoute(e route.RouteEntry) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	for fam, routes := range f.routes {
		i := slices.IndexFunc(routes, func(x route.RouteEntry) bool {
			return reflect.DeepEqual(x, e)
		})
		if i >= 0 {
			f.routes[fam] = slices.Delete(routes, i, i+1)
			return nil
		}
	}
	return syscall.ESRCH
}

// allRules returns the rules of every family, IPv4 first.
func (f *fakeNetlink) allRules() []route.Rule {
	return append(slices.Clone(f.rules[netutil.FamilyV4]), f.rules[netutil.FamilyV6]...)
}

// allRoutes returns the routes of every family, IPv4 first.
func (f *fakeNetlink) allRoutes() []route.RouteEntry {
	return append(
		slices.Clone(f.routes[netutil.FamilyV4]),
		f.routes[netutil.FamilyV6]...,
	)
}

// dumpedRule returns r as a dump shows it: the kernel does not dump a mark
// of 0, and dumps the protocol of every rule.
func dumpedRule(r route.Rule) route.Rule {
	if r.HasFwmark && r.Fwmark == 0 {
		r.HasFwmark = false
	}
	r.HasProtocol = true
	return r
}

// systemRules returns the rules of fam that the kernel creates.
func systemRules(fam netutil.Family) []route.Rule {
	var rules []route.Rule
	for _, r := range []route.Rule{
		lookupRule(0, 255),
		lookupRule(32766, mainTable),
		lookupRule(32767, 253),
	} {
		r.Family = fam
		r.Protocol, r.HasProtocol = 2, true
		rules = append(rules, r)
	}
	if fam == netutil.FamilyV6 {
		rules = slices.Delete(rules, 2, 3)
	}
	return rules
}

// defaultHostRules returns the system rules of both families.
func defaultHostRules() []route.Rule {
	return append(systemRules(netutil.FamilyV4), systemRules(netutil.FamilyV6)...)
}

// mainRoute returns a route in the main table of the host.
func mainRoute() route.RouteEntry {
	return route.RouteEntry{
		Table:    mainTable,
		Dst:      netip.MustParsePrefix("0.0.0.0/0"),
		Oif:      2,
		Gateway:  netip.MustParseAddr("192.168.1.1"),
		Protocol: 16,
		Type:     route.RouteTypeUnicast,
	}
}

// crashedIPv4 returns the IPv4 rules of a run that used table and the
// block of prefs starting at pref, as a dump shows them after a crash:
// the TUN and its routes are gone, the rules stay.
func crashedIPv4(table, pref uint32) []route.Rule {
	return []route.Rule{
		dumpedRule(mainLookupRule(netutil.FamilyV4, pref)),
		dumpedRule(fromRule(pref+1, netip.MustParseAddr("192.168.1.10"))),
		dumpedRule(captureRule(netutil.FamilyV4, pref+2, table)),
	}
}

// crashedIPv6 is crashedIPv4 for the IPv6 rules.
func crashedIPv6(table, pref uint32) []route.Rule {
	return []route.Rule{
		dumpedRule(mainLookupRule(netutil.FamilyV6, pref)),
		dumpedRule(captureRule(netutil.FamilyV6, pref+1, table)),
	}
}

// capturedRoutes returns the routes of a run in table as a dump shows
// them, with the TUN gone: such routes only stay when they were restored
// without it, such as by `ip route restore`.
func capturedRoutes(table uint32) []route.RouteEntry {
	v4 := captureRoute(netutil.FamilyV4, table, 0)
	v6 := captureRoute(netutil.FamilyV6, table, 0)
	v6.Metric = 1024
	return []route.RouteEntry{v4, v6}
}

// logLine is the part of a zerolog JSON line that the tests look at.
type logLine struct {
	Level         string `json:"level"`
	Message       string `json:"message"`
	Leftover      string `json:"leftover"`
	ManualCommand string `json:"manual_command"`
	Error         string `json:"error"`
}

// runCleanup runs cleanCaptureLeftovers on f and returns its log lines.
func runCleanup(t *testing.T, f *fakeNetlink) []logLine {
	t.Helper()
	var buf bytes.Buffer
	cleanCaptureLeftovers(zerolog.New(&buf), f)
	return parseLog(t, &buf)
}

func parseLog(t *testing.T, buf *bytes.Buffer) []logLine {
	t.Helper()
	var lines []logLine
	for l := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
		if l == "" {
			continue
		}
		var line logLine
		require.NoError(t, json.Unmarshal([]byte(l), &line))
		lines = append(lines, line)
	}
	return lines
}

// warnings returns the manual commands of the WARN lines.
func warnings(lines []logLine) []string {
	var cmds []string
	for _, l := range lines {
		if l.Level == "warn" {
			cmds = append(cmds, l.ManualCommand)
		}
	}
	return cmds
}

// removed returns the number of INFO lines about a removed leftover.
func removed(lines []logLine) int {
	n := 0
	for _, l := range lines {
		if l.Level == "info" && l.Leftover != "" {
			n++
		}
	}
	return n
}

const (
	tableA = captureTableFirst
	tableB = captureTableFirst + 1
)

func TestCleanCaptureLeftovers_NothingLeft(t *testing.T) {
	f := newFakeNetlink(defaultHostRules(), []route.RouteEntry{mainRoute()})
	lines := runCleanup(t, f)
	assert.Empty(t, lines)
	assert.Equal(t, defaultHostRules(), f.allRules())
}

func TestCleanCaptureLeftovers_CrashedRun(t *testing.T) {
	rules := defaultHostRules()
	rules = append(rules, crashedIPv4(tableA, 32763)...)
	rules = append(rules, crashedIPv6(tableA, 32764)...)
	f := newFakeNetlink(rules, []route.RouteEntry{mainRoute()})

	lines := runCleanup(t, f)

	assert.Equal(t, defaultHostRules(), f.allRules(), "every rule of the run is gone")
	assert.Equal(t, []route.RouteEntry{mainRoute()}, f.allRoutes())
	assert.Equal(t, 5, removed(lines))
	assert.Empty(t, warnings(lines))
}

func TestCleanCaptureLeftovers_RemovesOrder(t *testing.T) {
	rules := append(defaultHostRules(), crashedIPv4(tableA, 32763)...)
	f := newFakeNetlink(rules, capturedRoutes(tableA))

	var order []string
	f.beforeDelete = func(f *fakeNetlink) {
		order = append(order, strings.Join(describe(f), ","))
	}
	lines := runCleanup(t, f)

	assert.Equal(t, defaultHostRules(), f.allRules())
	assert.Empty(t, f.allRoutes(), "the tagged routes in the table are gone")
	assert.Equal(t, 5, removed(lines))
	assert.Equal(t, []string{
		"route4,route6,32763,32764,32765",
		"route6,32763,32764,32765",
		"32763,32764,32765",
		"32763,32765",
		"32765",
	}, order, "the routes go first, the anchor last")
}

// describe lists what is left of a run in f: its routes by family, and
// its tagged rules by pref.
func describe(f *fakeNetlink) []string {
	var s []string
	for _, e := range f.allRoutes() {
		if e.Dst.Addr().Is4() {
			s = append(s, "route4")
		} else {
			s = append(s, "route6")
		}
	}
	for _, r := range f.allRules() {
		if isTagged(r) {
			s = append(s, fmt.Sprint(r.Priority))
		}
	}
	return s
}

func TestCleanCaptureLeftovers_TUNAlive(t *testing.T) {
	rules := append(defaultHostRules(), crashedIPv4(tableA, 32763)...)
	f := newFakeNetlink(rules, nil)
	f.tunIndex = 9
	want := f.allRules()

	lines := runCleanup(t, f)

	assert.Equal(t, want, f.allRules(), "nothing is removed while a run is alive")
	require.Len(t, lines, 1)
	assert.Equal(t, "info", lines[0].Level)
	assert.Contains(t, lines[0].Message, linuxTUNName)
}

func TestCleanCaptureLeftovers_PersistentTUN(t *testing.T) {
	rules := append(defaultHostRules(), crashedIPv4(tableA, 32763)...)
	f := newFakeNetlink(rules, nil)
	f.tunIndex, f.tunPersistent = 9, true
	want := f.allRules()

	lines := runCleanup(t, f)

	assert.Equal(t, want, f.allRules(), "a persistent TUN still counts as alive")
	require.Len(t, lines, 1)
	assert.Equal(t, "warn", lines[0].Level)
	assert.Contains(t, lines[0].Message, "persistent "+linuxTUNName)
}

func TestCleanCaptureLeftovers_TUNAppears(t *testing.T) {
	rules := append(defaultHostRules(), crashedIPv4(tableA, 32763)...)
	f := newFakeNetlink(rules, nil)
	f.beforeDelete = func(f *fakeNetlink) { f.tunIndex = 9 }
	want := f.allRules()

	lines := runCleanup(t, f)

	assert.Equal(t, want, f.allRules(), "a run that starts meanwhile keeps its rules")
	assert.Len(t, warnings(lines), 3)
	for _, l := range lines {
		assert.Contains(t, l.Error, "another spoofdpi runs")
	}
}

func TestCleanCaptureLeftovers_PermissionDenied(t *testing.T) {
	rules := append(defaultHostRules(), crashedIPv4(tableA, 32763)...)
	f := newFakeNetlink(rules, nil)
	f.deleteErr = syscall.EPERM
	want := f.allRules()

	lines := runCleanup(t, f)

	assert.Equal(t, want, f.allRules())
	require.Len(t, warnings(lines), 3)
	assert.Contains(t, lines[0].Error, "run spoofdpi as root")
	assert.Contains(t, lines[1].Error, "run spoofdpi as root")
	assert.Contains(t, lines[2].Error, "tied to it remain")
	assert.Equal(t, []string{
		"ip rule del pref 32764 from 192.168.1.10 lookup main protocol 213",
		"ip rule del pref 32763 lookup main suppress_prefixlength 0 protocol 213",
		"ip rule del pref 32765 fwmark 0/0xffffffff lookup 1397769216 protocol 213",
	}, warnings(lines))
}

func TestCleanCaptureLeftovers_MultipleAnchors(t *testing.T) {
	rules := defaultHostRules()
	rules = append(rules, crashedIPv4(tableA, 32763)...)
	rules = append(rules, crashedIPv4(tableB, 32760)...)
	rules = append(rules, crashedIPv6(tableA, 32764)...)
	rules = append(rules, crashedIPv6(tableB, 32762)...)
	f := newFakeNetlink(rules, capturedRoutes(tableB))

	lines := runCleanup(t, f)

	assert.Equal(t, defaultHostRules(), f.allRules())
	assert.Empty(t, f.allRoutes())
	assert.Equal(t, 12, removed(lines))
	assert.Empty(t, warnings(lines))
}

func TestCleanCaptureLeftovers_IPv6Only(t *testing.T) {
	rules := append(defaultHostRules(), crashedIPv6(tableA, 32764)...)
	f := newFakeNetlink(rules, nil)

	lines := runCleanup(t, f)

	assert.Equal(t, defaultHostRules(), f.allRules())
	assert.Equal(t, 2, removed(lines))
	assert.Empty(t, warnings(lines))
}

func TestCleanCaptureLeftovers_PartialBlock(t *testing.T) {
	// The run crashed after the capture rule and the main lookup rule.
	crashed := crashedIPv4(tableA, 32763)
	rules := append(defaultHostRules(), crashed[0], crashed[2])
	f := newFakeNetlink(rules, nil)

	lines := runCleanup(t, f)

	assert.Equal(t, defaultHostRules(), f.allRules())
	assert.Equal(t, 2, removed(lines))
}

func TestCleanCaptureLeftovers_AmbiguousAnchor(t *testing.T) {
	// A tagged rule at the anchor's pref that looks up its table for a
	// nonzero mark: the delete of the anchor, whose mark 0 is a wildcard,
	// could remove it instead.
	marked := dumpedRule(captureRule(netutil.FamilyV4, 32765, tableA))
	marked.Fwmark, marked.HasFwmark = 0x1, true
	rules := append(defaultHostRules(), crashedIPv4(tableA, 32763)...)
	rules = append(rules, marked)
	f := newFakeNetlink(rules, nil)

	lines := runCleanup(t, f)

	left := f.allRules()
	assert.Contains(t, left, dumpedRule(captureRule(netutil.FamilyV4, 32765, tableA)))
	assert.Contains(t, left, marked)
	assert.Equal(t, 2, removed(lines), "the anchor's linked rules go")
	assert.ElementsMatch(t, []string{
		"ip rule del pref 32765 fwmark 0/0xffffffff lookup 1397769216 protocol 213",
		"ip rule del pref 32765 fwmark 0x1/0xffffffff lookup 1397769216 protocol 213",
	}, warnings(lines))
}

func TestCleanCaptureLeftovers_AmbiguousLinkedRuleKeepsAnchor(t *testing.T) {
	// A tagged `not` variant of the main lookup rule at its pref: the
	// kernel's delete does not compare the invert flag.
	notMain := dumpedRule(mainLookupRule(netutil.FamilyV4, 32763))
	notMain.Invert = true
	rules := append(defaultHostRules(), crashedIPv4(tableA, 32763)...)
	rules = append(rules, notMain)
	f := newFakeNetlink(rules, nil)

	lines := runCleanup(t, f)

	left := f.allRules()
	assert.Contains(t, left, dumpedRule(mainLookupRule(netutil.FamilyV4, 32763)))
	assert.Contains(t, left, dumpedRule(captureRule(netutil.FamilyV4, 32765, tableA)),
		"the anchor stays while a rule tied to it does")
	assert.Equal(t, 1, removed(lines), "only the from rule goes")
	assert.Len(t, warnings(lines), 3)
}

func TestCleanCaptureLeftovers_ForeignLeftAlone(t *testing.T) {
	wgMain := lookupRule(32764, mainTable)
	wgMain.SuppressPrefixlen, wgMain.HasSuppressPrefixlen = 0, true
	wgMain.HasProtocol = true
	wgCapture := markRule(32765, 0xca6c, 0xffffffff, 51820)
	wgCapture.Invert, wgCapture.HasProtocol = true, true

	untaggedMarkZero := dumpedRule(captureRule(netutil.FamilyV4, 32700, tableA))
	untaggedMarkZero.Protocol = 0

	tcs := []struct {
		name   string
		rules  []route.Rule
		routes []route.RouteEntry
		// warn are the manual commands of the warnings.
		warn []string
	}{
		{
			name:  "wg-quick rules without the tag",
			rules: []route.Rule{wgMain, wgCapture},
		},
		{
			name: "untagged capture rule in the capture range",
			rules: []route.Rule{
				untaggedMarkZero,
			},
		},
		{
			name:  "the anchor's table holds a foreign route",
			rules: crashedIPv4(tableA, 32763),
			routes: []route.RouteEntry{{
				Table:    tableA,
				Dst:      netip.MustParsePrefix("10.0.0.0/8"),
				Oif:      3,
				Protocol: 3,
				Scope:    route.RouteScopeLink,
				Type:     route.RouteTypeUnicast,
			}},
			warn: []string{
				"ip rule del pref 32763 lookup main suppress_prefixlength 0 protocol 213",
				"ip rule del pref 32764 from 192.168.1.10 lookup main protocol 213",
				"ip rule del pref 32765 fwmark 0/0xffffffff lookup 1397769216 protocol 213",
			},
		},
		{
			name: "an untagged rule looks up the anchor's table",
			rules: append(crashedIPv4(tableA, 32763), func() route.Rule {
				r := lookupRule(100, tableA)
				r.HasProtocol = true
				return r
			}()),
			warn: []string{
				"ip rule del pref 32763 lookup main suppress_prefixlength 0 protocol 213",
				"ip rule del pref 32764 from 192.168.1.10 lookup main protocol 213",
				"ip rule del pref 32765 fwmark 0/0xffffffff lookup 1397769216 protocol 213",
			},
		},
		{
			name:  "the anchor's table is outside the capture range",
			rules: crashedIPv4(captureTableLast+1, 32763),
			warn: []string{
				"ip rule del pref 32763 lookup main suppress_prefixlength 0 protocol 213",
				"ip rule del pref 32764 from 192.168.1.10 lookup main protocol 213",
				"ip rule del pref 32765 fwmark 0/0xffffffff lookup 1397769472 protocol 213",
			},
		},
		{
			name: "the capture rule comes after main",
			rules: []route.Rule{
				dumpedRule(captureRule(netutil.FamilyV4, 32767, tableA)),
			},
			warn: []string{
				"ip rule del pref 32767 fwmark 0/0xffffffff lookup 1397769216 protocol 213",
			},
		},
		{
			name: "a tagged capture rule without the mask",
			rules: []route.Rule{func() route.Rule {
				r := dumpedRule(captureRule(netutil.FamilyV4, 32765, tableA))
				r.Fwmask, r.HasFwmask = 0, false
				return r
			}()},
			warn: []string{"ip rule del pref 32765 lookup 1397769216 protocol 213"},
		},
		{
			name: "a tagged route outside the anchors' tables",
			routes: []route.RouteEntry{
				captureRoute(netutil.FamilyV4, tableB, 0),
			},
			warn: []string{"ip route del default table 1397769217 proto 213"},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			rules := append(defaultHostRules(), tc.rules...)
			routes := append([]route.RouteEntry{mainRoute()}, tc.routes...)
			f := newFakeNetlink(rules, routes)
			want := slices.Clone(f.allRules())

			lines := runCleanup(t, f)

			assert.Equal(t, want, f.allRules(), "no foreign rule is removed")
			assert.ElementsMatch(t, routes, f.allRoutes(), "no foreign route is removed")
			assert.Zero(t, removed(lines))
			assert.ElementsMatch(t, tc.warn, warnings(lines))
		})
	}
}

func TestCleanCaptureLeftovers_TaggedRuleFarFromAnchor(t *testing.T) {
	far := dumpedRule(mainLookupRule(netutil.FamilyV4, 32000))
	rules := append(defaultHostRules(), crashedIPv4(tableA, 32763)...)
	rules = append(rules, far)
	f := newFakeNetlink(rules, nil)

	lines := runCleanup(t, f)

	assert.Equal(t, newFakeNetlink(append(defaultHostRules(), far), nil).allRules(),
		f.allRules(), "the anchor's block goes, the rule far from it stays")
	assert.Equal(t, 3, removed(lines))
	assert.Equal(t, []string{
		"ip rule del pref 32000 lookup main suppress_prefixlength 0 protocol 213",
	}, warnings(lines))
}

func TestCleanCaptureLeftovers_LegacyLookalikes(t *testing.T) {
	untagged := func(r route.Rule) route.Rule {
		r = dumpedRule(r)
		r.Protocol = 0
		return r
	}
	notMarked := untagged(markRule(32765, egressFwmark, 0xffffffff, 201))
	notMarked.Invert = true
	markZero := untagged(captureRule(netutil.FamilyV4, 32760, 200))

	rules := append(defaultHostRules(),
		untagged(mainLookupRule(netutil.FamilyV4, 32758)),
		untagged(fromRule(32759, netip.MustParseAddr("192.168.1.10"))),
		markZero,
		untagged(mainLookupRule(netutil.FamilyV4, 32763)),
		untagged(fromRule(32764, netip.MustParseAddr("192.168.1.10"))),
		notMarked,
		untagged(mainLookupRule(netutil.FamilyV6, 32764)),
		untagged(captureRule(netutil.FamilyV6, 32765, 201)),
	)
	f := newFakeNetlink(rules, nil)
	want := slices.Clone(f.allRules())

	lines := runCleanup(t, f)

	assert.Equal(t, want, f.allRules(), "untagged rules are never removed")
	assert.Zero(t, removed(lines))
	assert.Equal(t, []string{
		"ip rule del pref 32758 lookup main suppress_prefixlength 0",
		"ip rule del pref 32759 from 192.168.1.10 lookup main",
		"ip rule del pref 32760 fwmark 0/0xffffffff lookup 200",
		"ip rule del pref 32763 lookup main suppress_prefixlength 0",
		"ip rule del pref 32764 from 192.168.1.10 lookup main",
		"ip rule del pref 32765 not fwmark 0x30d5/0xffffffff lookup 201",
		"ip -6 rule del pref 32764 lookup main suppress_prefixlength 0",
		"ip -6 rule del pref 32765 fwmark 0/0xffffffff lookup 201",
	}, warnings(lines))
}

func TestCleanCaptureLeftovers_V160Lookalikes(t *testing.T) {
	gw := netip.MustParseAddr("192.168.1.1")
	physIP := netip.MustParseAddr("192.168.1.10")
	from := func(pref, table uint32, src netip.Addr) route.Rule {
		r := lookupRule(pref, table)
		r.Src = netip.PrefixFrom(src, 32)
		r.HasProtocol = true
		return r
	}
	tableDefault := func(table uint32, proto uint8) route.RouteEntry {
		e := mainRoute()
		e.Table, e.Protocol = table, proto
		return e
	}
	gwHost := func(proto uint8) route.RouteEntry {
		return route.RouteEntry{
			Table:    mainTable,
			Dst:      netip.PrefixFrom(gw, 32),
			Oif:      2,
			Protocol: proto,
			Scope:    route.RouteScopeLink,
			Type:     route.RouteTypeUnicast,
		}
	}
	onLink := tableDefault(202, 3)
	onLink.Gateway = netip.Addr{}

	tcs := []struct {
		name   string
		rules  []route.Rule
		routes []route.RouteEntry
		warn   []string
	}{
		{
			name:   "v1.6.0 rule, table default and gateway host route",
			rules:  []route.Rule{from(32765, 201, physIP)},
			routes: []route.RouteEntry{gwHost(3), tableDefault(201, 3)},
			warn: []string{
				"ip rule del pref 32765 from 192.168.1.10 lookup 201",
				"ip route del default via 192.168.1.1 table 201 proto 3",
				"ip route del 192.168.1.1/32 table main proto 3",
			},
		},
		{
			name:   "a gateway host route of DHCP is not reported",
			rules:  []route.Rule{from(32765, 201, physIP)},
			routes: []route.RouteEntry{gwHost(16), tableDefault(201, 3)},
			warn: []string{
				"ip rule del pref 32765 from 192.168.1.10 lookup 201",
				"ip route del default via 192.168.1.1 table 201 proto 3",
			},
		},
		{
			name:   "a static table default is not spoofdpi's",
			rules:  []route.Rule{from(32765, 201, physIP)},
			routes: []route.RouteEntry{gwHost(3), tableDefault(201, 4)},
		},
		{
			name:   "a source that is not on the route's interface",
			rules:  []route.Rule{from(32765, 201, netip.MustParseAddr("10.9.9.9"))},
			routes: []route.RouteEntry{gwHost(3), tableDefault(201, 3)},
		},
		{
			name:   "a table without a gateway default route",
			rules:  []route.Rule{from(32764, 202, physIP)},
			routes: []route.RouteEntry{onLink},
		},
		{
			name:   "a table outside 200-250",
			rules:  []route.Rule{from(32763, 251, physIP)},
			routes: []route.RouteEntry{tableDefault(251, 3)},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			routes := append([]route.RouteEntry{mainRoute()}, tc.routes...)
			f := newFakeNetlink(append(defaultHostRules(), tc.rules...), routes)
			f.addrs = map[int][]netip.Addr{2: {physIP}}
			want := f.allRules()

			lines := runCleanup(t, f)

			assert.Equal(t, want, f.allRules(), "nothing is removed")
			assert.ElementsMatch(t, routes, f.allRoutes())
			assert.Zero(t, removed(lines))
			assert.Equal(t, tc.warn, warnings(lines))
			for _, l := range lines {
				assert.Contains(
					t,
					l.Message,
					"possible network configuration of spoofdpi v1.6.0",
				)
			}
		})
	}
}

func TestLeftoversAfterReset(t *testing.T) {
	run := captureRun{
		table: tableA,
		prefs: map[netutil.Family][]uint32{
			netutil.FamilyV4: {32763, 32764, 32765},
			netutil.FamilyV6: {32764, 32765},
		},
	}
	foreignAtPref := lookupRule(32764, 100)
	foreignAtPref.HasProtocol = true
	crashed := crashedIPv4(tableA, 32763)
	otherRun := crashedIPv4(tableB, 32760)

	f := newFakeNetlink(
		append(defaultHostRules(), crashed[2], foreignAtPref, otherRun[0]),
		[]route.RouteEntry{mainRoute(), captureRoute(netutil.FamilyV4, tableA, 7)},
	)
	f.tunIndex = 7
	snap, err := takeCaptureSnapshot(f)
	require.NoError(t, err)

	var cmds []string
	for _, l := range leftoversAfterReset(snap, run) {
		assert.Nil(t, l.Remove, "nothing is removed after a reset")
		cmds = append(cmds, l.ManualCommand)
	}
	assert.Equal(t, []string{
		"ip rule del pref 32765 fwmark 0/0xffffffff lookup 1397769216 protocol 213",
		"ip route del default table 1397769216 proto 213",
	}, cmds)

	clean := newFakeNetlink(defaultHostRules(), []route.RouteEntry{mainRoute()})
	snap, err = takeCaptureSnapshot(clean)
	require.NoError(t, err)
	assert.Empty(t, leftoversAfterReset(snap, run))
}

func TestRouteText(t *testing.T) {
	ifaces, err := net.Interfaces()
	require.NoError(t, err)
	if len(ifaces) == 0 {
		t.Skip("no network interface")
	}
	e := route.RouteEntry{
		Dst: netip.MustParsePrefix("192.0.2.0/24"),
		Oif: ifaces[0].Index,
	}
	assert.Contains(t, routeText(e), " dev "+ifaces[0].Name+" ")

	e.Oif = 1 << 30
	assert.Contains(
		t,
		routeText(e),
		" dev 1073741824 ",
		"a missing interface stays an index",
	)
}
