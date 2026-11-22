package server

import (
	"errors"
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

// ErrIPv4Only is the error of a destination that has no IPv4 address, while
// the selected rule sets ipv6 = false.
var ErrIPv4Only = errors.New(
	"the rule sets ipv6 = false and the destination has no IPv4 address",
)

// AllowedAddrs returns the addresses of addrs that a connection under the
// selected rule matched (nil when none matches) may use: only the IPv4
// ones when the rule sets ipv6 = false itself, else all of them, in the
// same order. An IPv4-mapped IPv6 address counts as IPv4. It returns
// ErrIPv4Only when the rule leaves no address.
func AllowedAddrs(matched *config.Rule, addrs []net.IP) ([]net.IP, error) {
	if !matched.IPv4Only() {
		return addrs, nil
	}

	allowed := make([]net.IP, 0, len(addrs))
	for _, ip := range addrs {
		if ip.To4() != nil {
			allowed = append(allowed, ip)
		}
	}
	if len(allowed) == 0 {
		return nil, ErrIPv4Only
	}
	return allowed, nil
}
