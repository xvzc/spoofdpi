package tun

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"reflect"
	"slices"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/route"
	"github.com/xvzc/spoofdpi/internal/server"
)

// captureFamilies are the address families of TUN mode's rules and routes.
var captureFamilies = []netutil.Family{netutil.FamilyV4, netutil.FamilyV6}

// captureNetlink reads and changes the kernel's rules and routes for the
// leftover search on Linux. Tests replace it with a fake.
type captureNetlink interface {
	// TUNIndex returns the index of linuxTUNName, or 0 when it does not
	// exist.
	TUNIndex() (int, error)
	// TUNPersistent reports whether linuxTUNName, which exists, is a
	// persistent TUN (IFF_PERSIST), which outlives the process that made it.
	TUNPersistent() (bool, error)
	// Rules and Routes dump fam; what the kernel does not support, such
	// as IPv6 or policy routing, dumps as empty.
	Rules(fam netutil.Family) ([]route.Rule, error)
	Routes(fam netutil.Family) ([]route.RouteEntry, error)
	// InterfaceAddrs returns the addresses of every interface by index.
	InterfaceAddrs() (map[int][]netip.Addr, error)
	DeleteRule(r route.Rule) error
	DeleteRoute(e route.RouteEntry) error
}

// captureSnapshot is a dump of the kernel's rules and routes.
type captureSnapshot struct {
	rules  map[netutil.Family][]route.Rule
	routes map[netutil.Family][]route.RouteEntry
	// tunIndex is the index of linuxTUNName, or 0 when it does not exist.
	tunIndex int
	// addrs are the addresses of every interface by index.
	addrs map[int][]netip.Addr
}

// takeCaptureSnapshot dumps the rules and routes of every family, and
// looks up the TUN interface.
func takeCaptureSnapshot(nl captureNetlink) (captureSnapshot, error) {
	snap := captureSnapshot{
		rules:  make(map[netutil.Family][]route.Rule),
		routes: make(map[netutil.Family][]route.RouteEntry),
	}
	var err error
	if snap.tunIndex, err = nl.TUNIndex(); err != nil {
		return captureSnapshot{}, err
	}
	if snap.addrs, err = nl.InterfaceAddrs(); err != nil {
		return captureSnapshot{}, err
	}
	for _, fam := range captureFamilies {
		if snap.rules[fam], err = nl.Rules(fam); err != nil {
			return captureSnapshot{}, err
		}
		if snap.routes[fam], err = nl.Routes(fam); err != nil {
			return captureSnapshot{}, err
		}
	}
	return snap, nil
}

// routeText describes e with the name of its interface, or its index when
// the interface is gone, for messages that a person reads.
func routeText(e route.RouteEntry) string {
	return e.StringWithNames(func(index int) string {
		if iface, err := net.InterfaceByIndex(index); err == nil {
			return iface.Name
		}
		return ""
	})
}

// captureAnchor is a capture rule that an earlier run left, with the rules
// tied to it.
type captureAnchor struct {
	rule route.Rule
	// linked are the rules of the anchor's block, in the order they are
	// removed: the from rule, then the main lookup rule.
	linked []route.Rule
}

// captureScan is what the leftover search finds in a captureSnapshot.
type captureScan struct {
	// anchors are the capture rules that may be removed, in dump order,
	// IPv4 first.
	anchors []captureAnchor
	// routes are the routes in the anchors' tables that may be removed.
	routes []route.RouteEntry
	// taggedRules and taggedRoutes carry TUN mode's tag but are not tied
	// to an anchor, so they are only reported.
	taggedRules  []route.Rule
	taggedRoutes []route.RouteEntry
	// legacyRules are untagged rules shaped like those of spoofdpi builds
	// that did not tag them, which are only reported.
	legacyRules []route.Rule
	// sourceRules and sourceRoutes are untagged rules and routes shaped
	// like those of spoofdpi v1.6.0 and earlier: `from <IP> lookup N`, N
	// within 200-250, whose table holds a default route through a
	// gateway, that route, and the main table's host route to the
	// gateway. They are only reported, as such a setup may be the user's
	// own source routing.
	sourceRules  []route.Rule
	sourceRoutes []route.RouteEntry
}

// lowestMainPref returns the pref of the lowest main rule of rules.
func lowestMainPref(rules []route.Rule) (uint32, bool) {
	var pref uint32
	found := false
	for _, r := range rules {
		if isMainRule(r) && (!found || r.Priority < pref) {
			pref, found = r.Priority, true
		}
	}
	return pref, found
}

// tableOwned reports whether table holds only what TUN mode adds: every
// route in it is tagged or leads into the TUN, and every rule that looks
// it up is tagged.
func (s captureSnapshot) tableOwned(table uint32) bool {
	for _, fam := range captureFamilies {
		for _, e := range s.routes[fam] {
			if e.Table != table || e.Protocol == captureProtocol {
				continue
			}
			if s.tunIndex == 0 || e.Oif != s.tunIndex {
				return false
			}
		}
		for _, r := range s.rules[fam] {
			if r.Table == table && !isTagged(r) {
				return false
			}
		}
	}
	return true
}

// isAnchor reports whether r, a rule of s of a family whose main rule is
// at mainPref, is a capture rule that only TUN mode adds.
func (s captureSnapshot) isAnchor(r route.Rule, mainPref uint32) bool {
	return isTagged(r) && isCaptureShape(r) && inCaptureTableRange(r.Table) &&
		r.Priority < mainPref && s.tableOwned(r.Table)
}

// linkedRules returns the tagged rules of anchor's block in rules: the
// from rule right before it (IPv4 only), and the main lookup rule right
// before that, in the order they are removed.
func linkedRules(anchor route.Rule, rules []route.Rule) []route.Rule {
	type slot struct {
		offset uint32
		shape  func(route.Rule) bool
	}
	slots := []slot{{1, isMainLookupShape}}
	if anchor.Family == netutil.FamilyV4 {
		slots = []slot{{1, isFromShape}, {2, isMainLookupShape}}
	}
	var linked []route.Rule
	for _, sl := range slots {
		if anchor.Priority <= sl.offset {
			break
		}
		pref := anchor.Priority - sl.offset
		for _, r := range rules {
			if r.Priority == pref && isTagged(r) && sl.shape(r) {
				linked = append(linked, r)
			}
		}
	}
	return linked
}

// isLegacyCapture reports whether r is shaped like the capture rule of a
// spoofdpi build that did not tag it: `not fwmark 0x30d5 lookup N` or
// `fwmark 0/0xffffffff lookup N`, N within 200-250, without the tag.
func isLegacyCapture(r route.Rule) bool {
	if isTagged(r) || r.Table < legacyTableFirst || r.Table > legacyTableLast ||
		r.Action != route.RuleActionToTable || r.TOS != 0 || r.Src.IsValid() ||
		r.HasSuppressPrefixlen || len(r.OtherAttrs) != 0 {
		return false
	}
	if r.Invert {
		mask := allMarksMask
		if r.HasFwmask {
			mask = r.Fwmask
		}
		return ruleMarkOf(r) == egressFwmark && mask == allMarksMask
	}
	return isCaptureShape(r)
}

// legacyRules returns the legacy capture rules of rules, a dump of fam in
// the kernel's order, and the untagged main lookup and from rules right
// before each of them, which such a build added with it.
func legacyRules(fam netutil.Family, rules []route.Rule) []route.Rule {
	maxBefore := 2
	if fam == netutil.FamilyV6 {
		maxBefore = 1
	}
	picked := make([]bool, len(rules))
	for i, r := range rules {
		if !isLegacyCapture(r) {
			continue
		}
		picked[i] = true
		for j := i - 1; j >= 0 && j >= i-maxBefore; j-- {
			b := rules[j]
			if isTagged(b) || b.Priority >= r.Priority ||
				!isMainLookupShape(b) && !isFromShape(b) {
				break
			}
			picked[j] = true
		}
	}
	var legacy []route.Rule
	for i, r := range rules {
		if picked[i] {
			legacy = append(legacy, r)
		}
	}
	return legacy
}

// isLegacySourceRule reports whether r is shaped like the rule of spoofdpi
// v1.6.0 and earlier: an untagged IPv4 `from <IP> lookup N`, N within
// 200-250.
func isLegacySourceRule(r route.Rule) bool {
	return !isTagged(r) && r.Family == netutil.FamilyV4 && isPlainLookup(r) &&
		r.Src.IsValid() && r.Src.IsSingleIP() && selectsNoMark(r) &&
		!r.HasSuppressPrefixlen &&
		r.Table >= legacyTableFirst && r.Table <= legacyTableLast
}

// gatewayDefaultRoute returns the IPv4 default route through a gateway in
// table that `ip route add` added (proto boot), if routes hold one.
func gatewayDefaultRoute(
	routes []route.RouteEntry,
	table uint32,
) (route.RouteEntry, bool) {
	for _, e := range routes {
		if e.Table == table && e.Dst.Bits() == 0 && e.Gateway.IsValid() &&
			e.Protocol == rtprotBoot {
			return e, true
		}
	}
	return route.RouteEntry{}, false
}

// rtprotBoot is the protocol of routes that `ip route add` adds without
// one (RTPROT_BOOT), as spoofdpi v1.6.0 added them.
const rtprotBoot uint8 = 3

// legacySource returns the rules and routes of s shaped like those of
// spoofdpi v1.6.0 and earlier (see captureScan.sourceRules): the rule's
// source is an address of the interface its table's default route leaves
// by, and both routes carry proto boot.
func legacySource(s captureSnapshot) ([]route.Rule, []route.RouteEntry) {
	var rules []route.Rule
	var routes []route.RouteEntry
	done := make(map[uint32]bool)
	v4Routes := s.routes[netutil.FamilyV4]
	for _, r := range s.rules[netutil.FamilyV4] {
		if !isLegacySourceRule(r) {
			continue
		}
		def, ok := gatewayDefaultRoute(v4Routes, r.Table)
		if !ok || !slices.Contains(s.addrs[def.Oif], r.Src.Addr()) {
			continue
		}
		rules = append(rules, r)
		if done[r.Table] {
			continue
		}
		done[r.Table] = true
		routes = append(routes, def)
		gwHost := netip.PrefixFrom(def.Gateway, def.Gateway.BitLen())
		for _, e := range v4Routes {
			if e.Table == mainTable && e.Dst == gwHost && !e.Gateway.IsValid() &&
				e.Oif == def.Oif && e.Protocol == rtprotBoot {
				routes = append(routes, e)
			}
		}
	}
	return rules, routes
}

// scanCapture finds in s the capture rules that earlier runs left, what is
// tied to them, and the rest of what looks like TUN mode's.
func scanCapture(s captureSnapshot) captureScan {
	var scan captureScan
	tables := make(map[uint32]bool)
	for _, fam := range captureFamilies {
		rules := s.rules[fam]
		claimed := make(map[int]bool)
		if mainPref, ok := lowestMainPref(rules); ok {
			for i, r := range rules {
				if !s.isAnchor(r, mainPref) {
					continue
				}
				a := captureAnchor{rule: r, linked: linkedRules(r, rules)}
				scan.anchors = append(scan.anchors, a)
				tables[r.Table] = true
				claimed[i] = true
				for j, l := range rules {
					if slices.ContainsFunc(a.linked, func(x route.Rule) bool {
						return reflect.DeepEqual(x, l)
					}) {
						claimed[j] = true
					}
				}
			}
		}
		for i, r := range rules {
			if isTagged(r) && !claimed[i] {
				scan.taggedRules = append(scan.taggedRules, r)
			}
		}
		scan.legacyRules = append(scan.legacyRules, legacyRules(fam, rules)...)
	}
	scan.sourceRules, scan.sourceRoutes = legacySource(s)
	for _, fam := range captureFamilies {
		for _, e := range s.routes[fam] {
			if e.Protocol != captureProtocol {
				continue
			}
			if tables[e.Table] && isCaptureRouteShape(e) {
				scan.routes = append(scan.routes, e)
			} else {
				scan.taggedRoutes = append(scan.taggedRoutes, e)
			}
		}
	}
	return scan
}

// errTUNAlive tells that a TUN mode run is alive, whose configuration
// must be left alone.
var errTUNAlive = errors.New(
	"interface " + linuxTUNName + " exists: another spoofdpi runs in TUN mode",
)

// captureLeftovers returns the leftovers of scan, a scan of a snapshot
// without the TUN interface. Each anchor's table routes come first, then
// the anchor's rules in the reverse of the order they were added, the
// anchor last, so a failure leaves the anchor to tie the rest to. The
// rules and routes that are not tied to an anchor come after, without a
// Remove.
func captureLeftovers(nl captureNetlink, scan captureScan) []server.Leftover {
	var leftovers []server.Leftover
	done := make(map[uint32]bool)
	for _, a := range scan.anchors {
		table := a.rule.Table
		if !done[table] {
			done[table] = true
			for _, e := range scan.routes {
				if e.Table == table {
					leftovers = append(leftovers, server.Leftover{
						Description:   "TUN mode route " + routeText(e),
						Remove:        removeCaptureRoute(nl, e),
						ManualCommand: ipRouteCommand("del", e, ""),
					})
				}
			}
		}
		for _, r := range a.linked {
			leftovers = append(leftovers, server.Leftover{
				Description:   "TUN mode rule " + r.String(),
				Remove:        removeCaptureRule(nl, r, false),
				ManualCommand: ipRuleCommand("del", r),
			})
		}
		leftovers = append(leftovers, server.Leftover{
			Description:   "TUN mode capture rule " + a.rule.String(),
			Remove:        removeCaptureRule(nl, a.rule, true),
			ManualCommand: ipRuleCommand("del", a.rule),
		})
	}
	for _, r := range scan.taggedRules {
		leftovers = append(leftovers, server.Leftover{
			Description: "rule tagged as TUN mode's but not tied to " +
				"its capture rule: " + r.String(),
			ManualCommand: ipRuleCommand("del", r),
		})
	}
	for _, e := range scan.taggedRoutes {
		leftovers = append(leftovers, server.Leftover{
			Description: "route tagged as TUN mode's but not tied to " +
				"its capture rule: " + routeText(e),
			ManualCommand: ipRouteCommand("del", e, ""),
		})
	}
	for _, r := range scan.legacyRules {
		leftovers = append(leftovers, server.Leftover{
			Description:   "untagged rule of an older spoofdpi build: " + r.String(),
			ManualCommand: ipRuleCommand("del", r),
		})
	}
	return leftovers
}

// warnLegacySource warns about the rules and routes of scan shaped like
// those of spoofdpi v1.6.0 and earlier, with the commands that remove
// them. They may be the user's own source routing, so they get a message
// of their own and are never removed.
func warnLegacySource(logger zerolog.Logger, scan captureScan) {
	warn := func(description, command string) {
		logger.Warn().
			Str("leftover", description).
			Str("manual_command", command).
			Msg("possible network configuration of spoofdpi v1.6.0; " +
				"remove it only if you did not set it up yourself")
	}
	for _, r := range scan.sourceRules {
		warn(r.String(), ipRuleCommand("del", r))
	}
	for _, e := range scan.sourceRoutes {
		warn(routeText(e), ipRouteCommand("del", e, ""))
	}
}

// rescan takes a fresh snapshot for a removal and scans it. It fails when
// the TUN interface has appeared since.
func rescan(nl captureNetlink) (captureSnapshot, captureScan, error) {
	snap, err := takeCaptureSnapshot(nl)
	if err != nil {
		return captureSnapshot{}, captureScan{}, err
	}
	if snap.tunIndex != 0 {
		return captureSnapshot{}, captureScan{}, errTUNAlive
	}
	return snap, scanCapture(snap), nil
}

// errNotLeftover tells that a fresh dump no longer shows a leftover as one
// that may be removed.
var errNotLeftover = errors.New(
	"no longer a removable leftover: gone, changed or no longer tied to " +
		"a capture rule",
)

// removeCaptureRoute returns the Remove of the route leftover e. It
// removes e only when a fresh dump still shows it as a leftover and the
// kernel's delete cannot hit another route.
func removeCaptureRoute(nl captureNetlink, e route.RouteEntry) func() error {
	return func() error {
		snap, scan, err := rescan(nl)
		if err != nil {
			return err
		}
		if !slices.ContainsFunc(scan.routes, func(x route.RouteEntry) bool {
			return reflect.DeepEqual(x, e)
		}) {
			return errNotLeftover
		}
		fam := netutil.FamilyV4
		if e.Dst.Addr().Is6() {
			fam = netutil.FamilyV6
		}
		if route.RouteDeleteAmbiguous(e, snap.routes[fam]) {
			return errors.New("the delete could remove another route; left in place")
		}
		return withRootHint(nl.DeleteRoute(e))
	}
}

// removeCaptureRule returns the Remove of the rule leftover r, an anchor
// or a rule linked to one. It removes r only when a fresh dump still shows
// it as such and the kernel's delete cannot hit another rule.
func removeCaptureRule(nl captureNetlink, r route.Rule, anchor bool) func() error {
	return func() error {
		snap, scan, err := rescan(nl)
		if err != nil {
			return err
		}
		if err := checkRuleLeftover(snap, scan, r, anchor); err != nil {
			return err
		}
		if route.RuleDeleteAmbiguous(r, snap.rules[r.Family]) {
			return errors.New("the delete could remove another rule; left in place")
		}
		return withRootHint(nl.DeleteRule(r))
	}
}

// checkRuleLeftover returns nil when scan, of snap, shows r as a rule
// linked to an anchor, or as an anchor that is ready to go: its table is
// empty and its linked rules are gone, so that nothing is left without an
// anchor to tie it to.
func checkRuleLeftover(
	snap captureSnapshot,
	scan captureScan,
	r route.Rule,
	anchor bool,
) error {
	for _, a := range scan.anchors {
		if !anchor {
			if slices.ContainsFunc(a.linked, func(x route.Rule) bool {
				return reflect.DeepEqual(x, r)
			}) {
				return nil
			}
			continue
		}
		if reflect.DeepEqual(a.rule, r) {
			if len(a.linked) != 0 || !snap.tableEmpty(r.Table) {
				return errors.New("left in place while rules or routes tied to it remain")
			}
			return nil
		}
	}
	return errNotLeftover
}

// tableEmpty reports whether no route of any family is in table.
func (s captureSnapshot) tableEmpty(table uint32) bool {
	for _, fam := range captureFamilies {
		if slices.ContainsFunc(s.routes[fam], func(e route.RouteEntry) bool {
			return e.Table == table
		}) {
			return false
		}
	}
	return true
}

// withRootHint adds a hint to run as root to a permission error.
func withRootHint(err error) error {
	if errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("%w (run spoofdpi as root to remove it)", err)
	}
	return err
}

// cleanCaptureLeftovers removes the rules and routes that earlier TUN mode
// runs left behind, and warns about the ones it must not remove. It
// removes nothing while a TUN mode run is alive.
func cleanCaptureLeftovers(logger zerolog.Logger, nl captureNetlink) {
	snap, err := takeCaptureSnapshot(nl)
	if err != nil {
		logger.Warn().Err(err).Msg("failed to look for leftover TUN mode rules and routes")
		return
	}
	if snap.tunIndex != 0 {
		if persistent, err := nl.TUNPersistent(); err != nil {
			logger.Debug().Err(err).Msg("failed to read the flags of " + linuxTUNName)
		} else if persistent {
			logger.Warn().Msg("a persistent " + linuxTUNName + " exists, which " +
				"spoofdpi never creates; leaving the TUN mode rules and routes " +
				"alone while it exists (remove it with: ip link delete " +
				linuxTUNName + ")")
			return
		}
		logger.Info().Msg("interface " + linuxTUNName + " exists, so another " +
			"spoofdpi runs in TUN mode; leaving its rules and routes alone")
		return
	}
	scan := scanCapture(snap)
	server.RemoveLeftovers(logger, captureLeftovers(nl, scan))
	warnLegacySource(logger, scan)
}

// captureRun holds the table and rule prefs of this run's jobs.
type captureRun struct {
	table uint32
	prefs map[netutil.Family][]uint32
}

// leftoversAfterReset returns what snap still holds of run after its jobs
// were reset: the tagged rules at its prefs, the rules that look up its
// table, and the routes in its table.
func leftoversAfterReset(snap captureSnapshot, run captureRun) []server.Leftover {
	var leftovers []server.Leftover
	for _, fam := range captureFamilies {
		for _, r := range snap.rules[fam] {
			atPref := isTagged(r) && slices.Contains(run.prefs[fam], r.Priority)
			if atPref || r.Table == run.table {
				leftovers = append(leftovers, server.Leftover{
					Description:   "TUN mode rule " + r.String(),
					ManualCommand: ipRuleCommand("del", r),
				})
			}
		}
	}
	for _, fam := range captureFamilies {
		for _, e := range snap.routes[fam] {
			if e.Table == run.table {
				leftovers = append(leftovers, server.Leftover{
					Description:   "TUN mode route " + routeText(e),
					ManualCommand: ipRouteCommand("del", e, ""),
				})
			}
		}
	}
	return leftovers
}
