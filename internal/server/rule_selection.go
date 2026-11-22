package server

import (
	"net"

	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/rule"
)

// SelectRule selects the rule for a destination given by its name, its
// addresses, or both, without resolving anything. The name is matched
// against the domain rules and the addresses against the CIDR rules, and
// the highest-priority of the two matches and the candidates is selected.
//
// The candidates are rules the caller already matched. A caller that
// already matched the name passes that rule as a candidate with an empty
// name, so the name is not matched twice. Nil candidates are ignored.
//
// A tie goes to the address match, then to the candidates in the order
// given, then to the name match.
//
// A name that is an IP literal is not matched as a domain name; it is the
// address when no addresses are given.
//
// It returns the selected rule, or nil when no rule matches, and the config
// to apply: the rule's config, or base when no rule matches. With a domain
// name and no addresses, only the name is matched, so the config's DNS
// options are the ones to resolve the name with.
func SelectRule(
	rules *rule.RuleSet,
	base *config.RuntimeConfig,
	name string,
	addrs []net.IP,
	candidates ...*config.Rule,
) (*config.Rule, *config.RuntimeConfig) {
	if ip := net.ParseIP(name); ip != nil {
		if len(addrs) == 0 {
			addrs = []net.IP{ip}
		}
		name = ""
	}

	matched := rules.MatchAddrs(addrs)
	for _, candidate := range candidates {
		matched = rule.HigherPriority(matched, candidate)
	}
	matched = rule.HigherPriority(matched, rules.MatchName(name))
	if matched == nil {
		return nil, base
	}

	return matched, &matched.Config
}
