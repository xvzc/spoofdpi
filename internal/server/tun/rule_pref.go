package tun

import (
	"fmt"
	"strconv"
	"strings"
)

// freeRulePrefs picks n unused rule preferences that sit below the rule
// "from all lookup main" in ruleShowOutput, the output of "ip rule show" or
// "ip -6 rule show". It returns them in ascending order.
//
// It prefers the n highest prefs between the main rule and the highest
// other rule below it, so the new rules come after every rule already
// installed. When that gap is too small, it takes the n highest free prefs
// below the main rule instead, and returns as ahead the lines of the
// existing rules that now come after the lowest new rule: the new rules are
// placed before or among them. Pref 0 is never picked.
//
// When several rules read "from all lookup main", the lowest one is used,
// as the lookup ends at it.
func freeRulePrefs(
	ruleShowOutput string,
	n int,
) (prefs []int, ahead []string, err error) {
	type ruleLine struct {
		pref int
		line string
	}
	var rules []ruleLine
	used := make(map[int]bool)
	mainPref := -1
	for raw := range strings.SplitSeq(ruleShowOutput, "\n") {
		line := strings.TrimSpace(raw)
		prefText, selector, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		pref, convErr := strconv.ParseUint(prefText, 10, 32)
		if convErr != nil {
			continue
		}
		p := int(pref)
		rules = append(rules, ruleLine{pref: p, line: line})
		used[p] = true
		if isMainRule(selector) && (mainPref < 0 || p < mainPref) {
			mainPref = p
		}
	}
	if mainPref < 0 {
		return nil, nil, fmt.Errorf("no rule \"from all lookup main\" found")
	}

	highestBelowMain := 0
	for _, r := range rules {
		if r.pref < mainPref && r.pref > highestBelowMain {
			highestBelowMain = r.pref
		}
	}
	if mainPref-highestBelowMain-1 >= n {
		for p := mainPref - n; p < mainPref; p++ {
			prefs = append(prefs, p)
		}
		return prefs, nil, nil
	}

	for p := mainPref - 1; p > 0 && len(prefs) < n; p-- {
		if !used[p] {
			prefs = append([]int{p}, prefs...)
		}
	}
	if len(prefs) < n {
		return nil, nil, fmt.Errorf(
			"only %d free rule prefs below %d, need %d",
			len(prefs),
			mainPref,
			n,
		)
	}
	for _, r := range rules {
		if r.pref > prefs[0] && r.pref < mainPref {
			ahead = append(ahead, r.line)
		}
	}
	return prefs, ahead, nil
}

// isMainRule reports whether selector, a rule line after its pref, is the
// system's "from all lookup main" rule.
func isMainRule(selector string) bool {
	s := strings.Join(strings.Fields(selector), " ")
	return s == "from all lookup main" || s == "from all lookup main proto kernel"
}

// tunRulePrefs holds the prefs of TUN mode's rules on Linux.
type tunRulePrefs struct {
	main        int
	from        int
	capture     int
	ipv6Main    int
	ipv6Capture int
}

// assignRulePrefs maps the prefs chosen by freeRulePrefs to TUN mode's
// rules: ipv4 holds three prefs, and ipv6 two or none, which leaves the
// IPv6 prefs 0.
func assignRulePrefs(ipv4, ipv6 []int) tunRulePrefs {
	p := tunRulePrefs{main: ipv4[0], from: ipv4[1], capture: ipv4[2]}
	if len(ipv6) == 2 {
		p.ipv6Main, p.ipv6Capture = ipv6[0], ipv6[1]
	}
	return p
}
