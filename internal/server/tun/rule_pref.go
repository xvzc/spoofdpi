package tun

import (
	"fmt"

	"github.com/xvzc/spoofdpi/internal/route"
)

// freeRulePrefs picks n consecutive unused rule preferences that sit below
// the main rule ("from all lookup main") of rules, a rule dump of one
// address family. It returns them in ascending order.
//
// It prefers the n highest prefs between the main rule and the highest
// other rule below it, so the new rules come after every rule already
// installed. When that gap is too small, it takes the highest n consecutive
// free prefs below the main rule instead, and returns as ahead the existing
// rules that now come after the lowest new rule: the new rules are placed
// before these rules. Pref 0 is never picked.
//
// When there are several main rules, the lowest one is used, as the lookup
// ends at it.
func freeRulePrefs(
	rules []route.Rule,
	n int,
) (prefs []uint32, ahead []route.Rule, err error) {
	used := make(map[int64]bool)
	mainPref := int64(-1)
	for _, r := range rules {
		p := int64(r.Priority)
		used[p] = true
		if isMainRule(r) && (mainPref < 0 || p < mainPref) {
			mainPref = p
		}
	}
	if mainPref < 0 {
		return nil, nil, fmt.Errorf("no rule \"from all lookup main\" found")
	}

	var highestBelowMain int64
	for _, r := range rules {
		if p := int64(r.Priority); p < mainPref && p > highestBelowMain {
			highestBelowMain = p
		}
	}
	lowest := int64(-1)
	if mainPref-highestBelowMain-1 >= int64(n) {
		lowest = mainPref - int64(n)
	} else {
		run := int64(0)
		for p := mainPref - 1; p > 0; p-- {
			if used[p] {
				run = 0
				continue
			}
			if run++; run == int64(n) {
				lowest = p
				break
			}
		}
		if lowest < 0 {
			return nil, nil, fmt.Errorf(
				"no %d consecutive free rule prefs below %d",
				n,
				mainPref,
			)
		}
		for _, r := range rules {
			if p := int64(r.Priority); p > lowest && p < mainPref {
				ahead = append(ahead, r)
			}
		}
	}
	for p := lowest; p < lowest+int64(n); p++ {
		prefs = append(prefs, uint32(p))
	}
	return prefs, ahead, nil
}

// tunRulePrefs holds the prefs of TUN mode's rules on Linux.
type tunRulePrefs struct {
	main        uint32
	from        uint32
	capture     uint32
	ipv6Main    uint32
	ipv6Capture uint32
}

// assignRulePrefs maps the prefs chosen by freeRulePrefs to TUN mode's
// rules: ipv4 holds three prefs, and ipv6 two or none, which leaves the
// IPv6 prefs 0.
func assignRulePrefs(ipv4, ipv6 []uint32) tunRulePrefs {
	p := tunRulePrefs{main: ipv4[0], from: ipv4[1], capture: ipv4[2]}
	if len(ipv6) == 2 {
		p.ipv6Main, p.ipv6Capture = ipv6[0], ipv6[1]
	}
	return p
}
