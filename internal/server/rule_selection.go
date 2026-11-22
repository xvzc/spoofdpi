package server

import (
	"context"
	"errors"
	"net"

	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/dns"
	"github.com/xvzc/spoofdpi/internal/rule"
)

// Selection is the rule selected for a destination.
type Selection struct {
	// Rule is the selected rule, or nil when no rule matches.
	Rule *config.Rule
	// Config is the selected rule's config, or the base config when no rule
	// matches.
	Config *config.RuntimeConfig
	// Addrs are the destination's addresses: the given ones, or the ones
	// its name resolved to.
	Addrs []net.IP
}

// Blocked reports whether the selected rule blocks the destination.
func (s Selection) Blocked() bool {
	return s.Rule != nil && s.Rule.Block
}

// SelectRule selects the rule for a destination given by its name, its
// addresses, or both. The name is matched against the domain rules. When
// no addresses are given, the name is resolved with the DNS options of the
// domain rule it matches, else with base.DNS; resolver is only used then,
// and may be nil when addrs is not empty. The addresses are matched against
// the CIDR rules, and the higher-priority of the two matches is selected;
// the address match wins a tie.
//
// A name that is an IP literal is not matched as a domain name; it is the
// address when no addresses are given. An error from resolver is returned
// unchanged.
func SelectRule(
	ctx context.Context,
	rules *rule.RuleSet,
	resolver dns.Resolver,
	base *config.RuntimeConfig,
	name string,
	addrs []net.IP,
) (Selection, error) {
	if ip := net.ParseIP(name); ip != nil {
		if len(addrs) == 0 {
			addrs = []net.IP{ip}
		}
		name = ""
	}

	if name == "" && len(addrs) == 0 {
		return Selection{}, errors.New("no name or address to select a rule for")
	}

	domainMatch := rules.MatchName(name)

	if len(addrs) == 0 {
		opts := &base.DNS
		if domainMatch != nil {
			opts = &domainMatch.Config.DNS
		}

		resolved, err := resolver.Resolve(ctx, opts, name)
		if err != nil {
			return Selection{}, err
		}

		addrs = make([]net.IP, len(resolved))
		for i, a := range resolved {
			addrs[i] = a.AsSlice()
		}
	}

	matched := rule.HigherPriority(rules.MatchAddrs(addrs), domainMatch)

	sel := Selection{Rule: matched, Config: base, Addrs: addrs}
	if matched != nil {
		sel.Config = &matched.Config
	}

	return sel, nil
}
