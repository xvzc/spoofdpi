package tun

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/route"
)

// The rules and routes that TUN mode adds on Linux. They live here, apart
// from the Linux-only code that applies them, so that the code that tells
// them apart from everyone else's is tested on every OS.

// egressFwmark marks every socket TUN mode sends through the physical
// interface, so the capture rule, which matches only unmarked packets, passes
// them by. Any nonzero mark would do; this one avoids the bits that
// kube-proxy (0x4000, 0x8000), Cilium (0x0f00), Calico (0xffff0000) and
// Tailscale (0xff0000) use.
const egressFwmark = 0x30d5

const (
	// linuxTUNName is the name of the TUN interface on Linux. The kernel
	// removes the interface when the process that created it ends, so it
	// exists only while a TUN mode run is alive.
	linuxTUNName = "tun-spoofdpi"

	// captureProtocol tags every rule (FRA_PROTOCOL) and route
	// (rtm_protocol) that TUN mode adds, so that a later run can tell them
	// apart from the ones of others.
	captureProtocol uint8 = 213

	// captureTableFirst and captureTableLast bound the capture table IDs,
	// a range that only spoofdpi uses ("SPD" and a byte).
	captureTableFirst uint32 = 0x53504400
	captureTableLast  uint32 = 0x535044ff

	// mainTable is the ID of the main routing table (RT_TABLE_MAIN).
	mainTable uint32 = 254

	// allMarksMask is the mark mask of the capture rule: only packets whose
	// whole mark is 0 match.
	allMarksMask uint32 = 0xffffffff

	// legacyTableFirst and legacyTableLast bound the capture table IDs of
	// spoofdpi builds whose rules carry no tag.
	legacyTableFirst uint32 = 200
	legacyTableLast  uint32 = 250
)

// ipv6CapturePrefix is ipv6CaptureCIDR as a prefix.
var ipv6CapturePrefix = netip.MustParsePrefix(ipv6CaptureCIDR)

// captureRule returns the rule of fam at pref that sends unmarked packets
// to table, the capture rule. It is the anchor of the leftover search.
func captureRule(fam netutil.Family, pref, table uint32) route.Rule {
	return route.Rule{
		Family:      fam,
		Priority:    pref,
		Table:       table,
		Action:      route.RuleActionToTable,
		Fwmark:      0,
		HasFwmark:   true,
		Fwmask:      allMarksMask,
		HasFwmask:   true,
		Protocol:    captureProtocol,
		HasProtocol: true,
	}
}

// mainLookupRule returns the rule of fam at pref that looks up the main
// table without its default route.
func mainLookupRule(fam netutil.Family, pref uint32) route.Rule {
	return route.Rule{
		Family:               fam,
		Priority:             pref,
		Table:                mainTable,
		Action:               route.RuleActionToTable,
		SuppressPrefixlen:    0,
		HasSuppressPrefixlen: true,
		Protocol:             captureProtocol,
		HasProtocol:          true,
	}
}

// fromRule returns the IPv4 rule at pref that looks up the main table in
// full for traffic from src.
func fromRule(pref uint32, src netip.Addr) route.Rule {
	return route.Rule{
		Family:      netutil.FamilyV4,
		Priority:    pref,
		Src:         netip.PrefixFrom(src, src.BitLen()),
		Table:       mainTable,
		Action:      route.RuleActionToTable,
		Protocol:    captureProtocol,
		HasProtocol: true,
	}
}

// captureRoute returns the route of fam in table that leads into the TUN
// with index oif: the default route for IPv4, ipv6CaptureCIDR for IPv6.
func captureRoute(fam netutil.Family, table uint32, oif int) route.RouteEntry {
	e := route.RouteEntry{
		Table:    table,
		Dst:      netip.PrefixFrom(netip.IPv4Unspecified(), 0),
		Oif:      oif,
		Protocol: captureProtocol,
		Scope:    route.RouteScopeLink,
		Type:     route.RouteTypeUnicast,
	}
	if fam == netutil.FamilyV6 {
		e.Dst = ipv6CapturePrefix
		e.Scope = route.RouteScopeUniverse
	}
	return e
}

// isTagged reports whether r carries TUN mode's tag.
func isTagged(r route.Rule) bool {
	return r.HasProtocol && r.Protocol == captureProtocol
}

// ruleMarkOf returns the mark that r selects, 0 for none.
func ruleMarkOf(r route.Rule) uint32 {
	if r.HasFwmark {
		return r.Fwmark
	}
	return 0
}

// isPlainLookup reports whether r looks up a table and selects nothing but
// what TUN mode's rules may select: no TOS, no `not` and no selector that
// route.Rule does not hold.
func isPlainLookup(r route.Rule) bool {
	return r.Action == route.RuleActionToTable && !r.Invert && r.TOS == 0 &&
		len(r.OtherAttrs) == 0
}

// isCaptureShape reports whether r has the shape of captureRule, whatever
// its tag and table: it selects exactly the packets whose mark is 0.
func isCaptureShape(r route.Rule) bool {
	return isPlainLookup(r) && !r.Src.IsValid() && ruleMarkOf(r) == 0 &&
		r.HasFwmask && r.Fwmask == allMarksMask && !r.HasSuppressPrefixlen
}

// selectsNoMark reports whether r selects no mark at all.
func selectsNoMark(r route.Rule) bool {
	return ruleMarkOf(r) == 0 && (!r.HasFwmask || r.Fwmask == 0)
}

// isMainLookupShape reports whether r has the shape of mainLookupRule,
// whatever its tag.
func isMainLookupShape(r route.Rule) bool {
	return isPlainLookup(r) && !r.Src.IsValid() && selectsNoMark(r) &&
		r.Table == mainTable && r.HasSuppressPrefixlen && r.SuppressPrefixlen == 0
}

// isFromShape reports whether r has the shape of fromRule, whatever its
// tag and source address.
func isFromShape(r route.Rule) bool {
	return r.Family == netutil.FamilyV4 && isPlainLookup(r) && r.Src.IsValid() &&
		r.Src.IsSingleIP() && selectsNoMark(r) && r.Table == mainTable &&
		!r.HasSuppressPrefixlen
}

// isMainRule reports whether r is the system's "from all lookup main" rule,
// whatever its tag.
func isMainRule(r route.Rule) bool {
	return isPlainLookup(r) && !r.Src.IsValid() && selectsNoMark(r) &&
		r.Table == mainTable && !r.HasSuppressPrefixlen
}

// isCaptureRouteShape reports whether e has the shape of captureRoute,
// whatever its tag, table and output link.
func isCaptureRouteShape(e route.RouteEntry) bool {
	if e.Gateway.IsValid() || e.Type != route.RouteTypeUnicast || e.TOS != 0 {
		return false
	}
	if e.Dst.Addr().Is4() {
		return e.Dst.Bits() == 0 && e.Scope == route.RouteScopeLink
	}
	return e.Dst == ipv6CapturePrefix
}

// inCaptureTableRange reports whether table is a capture table ID.
func inCaptureTableRange(table uint32) bool {
	return table >= captureTableFirst && table <= captureTableLast
}

// freeCaptureTable returns the lowest capture table ID that no route of
// routes is in and no rule of rules looks up. rules and routes are dumps of
// both address families, since the capture table holds IPv4 and IPv6
// routes.
func freeCaptureTable(rules []route.Rule, routes []route.RouteEntry) (uint32, error) {
	used := make(map[uint32]bool)
	for _, r := range rules {
		used[r.Table] = true
	}
	for _, e := range routes {
		used[e.Table] = true
	}
	for id := captureTableFirst; id <= captureTableLast; id++ {
		if !used[id] {
			return id, nil
		}
	}
	return 0, fmt.Errorf(
		"no available routing table ID in range %#x-%#x",
		captureTableFirst,
		captureTableLast,
	)
}

// ipFamilyFlag returns the `ip` option that selects fam, with a trailing
// space, or "" for IPv4.
func ipFamilyFlag(fam netutil.Family) string {
	if fam == netutil.FamilyV6 {
		return "-6 "
	}
	return ""
}

// ipHex formats v as `ip rule` prints marks: 0, or hexadecimal.
func ipHex(v uint32) string {
	if v == 0 {
		return "0"
	}
	return fmt.Sprintf("%#x", v)
}

// ipTable formats table as `ip` takes it.
func ipTable(table uint32) string {
	if table == mainTable {
		return "main"
	}
	return fmt.Sprint(table)
}

// ipRuleCommand returns the `ip rule` command line that does verb, such as
// add or del, to r. It covers the selectors of route.Rule only: a rule with
// OtherAttrs reads as a broader one.
func ipRuleCommand(verb string, r route.Rule) string {
	var b strings.Builder
	fmt.Fprintf(&b, "ip %srule %s pref %d", ipFamilyFlag(r.Family), verb, r.Priority)
	if r.Invert {
		b.WriteString(" not")
	}
	if r.Src.IsValid() {
		if r.Src.IsSingleIP() {
			fmt.Fprintf(&b, " from %s", r.Src.Addr())
		} else {
			fmt.Fprintf(&b, " from %s", r.Src)
		}
	}
	if r.TOS != 0 {
		fmt.Fprintf(&b, " tos %#x", r.TOS)
	}
	if r.HasFwmark || r.HasFwmask {
		fmt.Fprintf(&b, " fwmark %s", ipHex(ruleMarkOf(r)))
		if r.HasFwmask {
			fmt.Fprintf(&b, "/%s", ipHex(r.Fwmask))
		}
	}
	fmt.Fprintf(&b, " lookup %s", ipTable(r.Table))
	if r.HasSuppressPrefixlen {
		fmt.Fprintf(&b, " suppress_prefixlength %d", r.SuppressPrefixlen)
	}
	if r.HasProtocol && r.Protocol != 0 {
		fmt.Fprintf(&b, " protocol %d", r.Protocol)
	}
	return b.String()
}

// ipRouteCommand returns the `ip route` command line that does verb, such
// as add or del, to e, whose output link is named dev, or "" to leave the
// link out.
func ipRouteCommand(verb string, e route.RouteEntry, dev string) string {
	fam := netutil.FamilyV4
	if e.Dst.Addr().Is6() {
		fam = netutil.FamilyV6
	}
	dst := e.Dst.String()
	if e.Dst.Bits() == 0 {
		dst = "default"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "ip %sroute %s %s", ipFamilyFlag(fam), verb, dst)
	if e.Gateway.IsValid() {
		fmt.Fprintf(&b, " via %s", e.Gateway)
	}
	if dev != "" {
		fmt.Fprintf(&b, " dev %s", dev)
	}
	fmt.Fprintf(&b, " table %s", ipTable(e.Table))
	if e.Protocol != 0 {
		fmt.Fprintf(&b, " proto %d", e.Protocol)
	}
	return b.String()
}
