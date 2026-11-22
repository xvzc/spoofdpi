package server

import (
	"net"

	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/rule"
)

// SelectRule selects the rule for a destination given by its name, its
// addresses, or both, without resolving anything. The name is matched
// against the domain rules and the addresses against the CIDR rules, and
// the higher-priority of the two matches is selected; the address match
// wins a tie.
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
) (*config.Rule, *config.RuntimeConfig) {
	if ip := net.ParseIP(name); ip != nil {
		if len(addrs) == 0 {
			addrs = []net.IP{ip}
		}
		name = ""
	}

	matched := rule.HigherPriority(rules.MatchAddrs(addrs), rules.MatchName(name))
	if matched == nil {
		return nil, base
	}

	return matched, &matched.Config
}
