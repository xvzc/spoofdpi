package server

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/rule"
)

// selectionRule returns a rule whose DNS options are tagged with its name.
func selectionRule(
	name string,
	priority uint16,
	domains, cidrs []string,
) *config.Rule {
	r := &config.Rule{
		Name:     name,
		Priority: priority,
		Match:    &config.MatchAttrs{Domains: domains, CIDRs: cidrs},
	}
	r.Config.DNS.HTTPSURL = name
	return r
}

func ips(ss ...string) []net.IP {
	out := make([]net.IP, len(ss))
	for i, s := range ss {
		out[i] = net.ParseIP(s)
	}
	return out
}

func newRuleSet(t *testing.T, rules ...*config.Rule) *rule.RuleSet {
	t.Helper()
	rs := rule.NewRuleSet()
	for _, r := range rules {
		require.NoError(t, rs.Add(r))
	}
	return rs
}

func TestSelectRule(t *testing.T) {
	const name = "example.com"

	domain := func(priority uint16) *config.Rule {
		return selectionRule("domain", priority, []string{name}, nil)
	}
	addr := func(priority uint16) *config.Rule {
		return selectionRule("addr", priority, nil, []string{"192.0.2.0/24"})
	}

	tcs := []struct {
		name     string
		rules    []*config.Rule
		host     string
		addrs    []net.IP
		wantRule string // "" for no rule
	}{
		{
			name:     "domain rule matches the name",
			rules:    []*config.Rule{domain(10)},
			host:     name,
			wantRule: "domain",
		},
		{
			name:     "address rule matches the addresses",
			rules:    []*config.Rule{addr(10)},
			host:     name,
			addrs:    ips("192.0.2.1"),
			wantRule: "addr",
		},
		{
			name:     "higher-priority domain rule wins",
			rules:    []*config.Rule{domain(20), addr(10)},
			host:     name,
			addrs:    ips("192.0.2.1"),
			wantRule: "domain",
		},
		{
			name:     "higher-priority address rule wins",
			rules:    []*config.Rule{domain(10), addr(20)},
			host:     name,
			addrs:    ips("192.0.2.1"),
			wantRule: "addr",
		},
		{
			name:     "address rule wins a tie",
			rules:    []*config.Rule{domain(10), addr(10)},
			host:     name,
			addrs:    ips("192.0.2.1"),
			wantRule: "addr",
		},
		{
			name:     "any address matches",
			rules:    []*config.Rule{addr(10)},
			addrs:    ips("198.51.100.1", "192.0.2.1"),
			wantRule: "addr",
		},
		{
			name:     "addresses only",
			rules:    []*config.Rule{domain(20), addr(10)},
			addrs:    ips("192.0.2.1"),
			wantRule: "addr",
		},
		{
			name: "ip literal name without addresses is the address",
			rules: []*config.Rule{
				selectionRule("literal", 20, []string{"192.0.2.1"}, nil),
				addr(10),
			},
			host:     "192.0.2.1",
			wantRule: "addr",
		},
		{
			name: "ip literal name with addresses is ignored",
			rules: []*config.Rule{
				selectionRule("literal", 20, []string{"192.0.2.1"}, nil),
				addr(10),
			},
			host:  "192.0.2.1",
			addrs: ips("198.51.100.1"),
		},
		{
			name:  "no rule matches",
			rules: []*config.Rule{domain(10), addr(10)},
			host:  "other.test",
			addrs: ips("198.51.100.1"),
		},
		{
			name: "no name or address",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			rs := newRuleSet(t, tc.rules...)
			base := &config.RuntimeConfig{}

			matched, cfg := SelectRule(rs, base, tc.host, tc.addrs)

			if tc.wantRule == "" {
				assert.Nil(t, matched)
				assert.Same(t, base, cfg)
			} else if assert.NotNil(t, matched) {
				assert.Equal(t, tc.wantRule, matched.Name)
				assert.Same(t, &matched.Config, cfg)
			}
		})
	}
}

func TestSelectRule_NilRuleSet(t *testing.T) {
	base := &config.RuntimeConfig{}

	matched, cfg := SelectRule(nil, base, "example.com", ips("192.0.2.1"))

	assert.Nil(t, matched)
	assert.Same(t, base, cfg)
}

func TestSelectRule_NameOnlyGivesLookupConfig(t *testing.T) {
	rs := newRuleSet(t,
		selectionRule("domain", 10, []string{"example.com"}, nil),
		selectionRule("addr", 20, nil, []string{"0.0.0.0/0"}),
	)

	tcs := []struct {
		name    string
		host    string
		wantDNS string // HTTPSURL tag of the config's DNS options
	}{
		{"domain match gives the domain rule's config", "example.com", "domain"},
		{"no domain match gives base", "other.test", "base"},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			base := &config.RuntimeConfig{}
			base.DNS.HTTPSURL = "base"

			_, cfg := SelectRule(rs, base, tc.host, nil)

			assert.Equal(t, tc.wantDNS, cfg.DNS.HTTPSURL)
			if tc.wantDNS == "base" {
				assert.Same(t, base, cfg)
			}
		})
	}
}

func TestSelectRule_Candidates(t *testing.T) {
	const name = "example.com"
	hostAddrs := ips("192.0.2.1")

	t.Run("candidate beats a lower-priority address match", func(t *testing.T) {
		cand := selectionRule("cand", 20, []string{name}, nil)
		addr := selectionRule("addr", 10, nil, []string{"192.0.2.0/24"})
		rs := newRuleSet(t, cand, addr)

		matched, cfg := SelectRule(
			rs,
			&config.RuntimeConfig{},
			"",
			hostAddrs,
			cand,
		)

		assert.Same(t, cand, matched)
		assert.Same(t, &cand.Config, cfg)
	})

	t.Run("address match wins a tie with a candidate", func(t *testing.T) {
		cand := selectionRule("cand", 10, []string{name}, nil)
		addr := selectionRule("addr", 10, nil, []string{"192.0.2.0/24"})
		rs := newRuleSet(t, cand, addr)

		matched, _ := SelectRule(
			rs,
			&config.RuntimeConfig{},
			"",
			hostAddrs,
			cand,
		)

		require.NotNil(t, matched)
		assert.Equal(t, addr.Name, matched.Name)
	})

	t.Run("candidate wins a tie with the name match", func(t *testing.T) {
		cand := selectionRule("cand", 10, nil, nil)
		dom := selectionRule("domain", 10, []string{name}, nil)
		rs := newRuleSet(t, dom)

		matched, _ := SelectRule(
			rs,
			&config.RuntimeConfig{},
			name,
			nil,
			cand,
		)

		assert.Same(t, cand, matched)
	})

	t.Run("nil candidate is ignored", func(t *testing.T) {
		base := &config.RuntimeConfig{}
		addr := selectionRule("addr", 10, nil, []string{"192.0.2.0/24"})
		rs := newRuleSet(t, addr)

		matched, _ := SelectRule(rs, base, "", hostAddrs, nil)
		require.NotNil(t, matched)
		assert.Equal(t, addr.Name, matched.Name)

		matched, cfg := SelectRule(rs, base, "", ips("198.51.100.1"), nil)
		assert.Nil(t, matched)
		assert.Same(t, base, cfg)
	})

	t.Run("candidate with an empty name equals the two-call result", func(t *testing.T) {
		for _, domPriority := range []uint16{5, 10, 20} {
			dom := selectionRule("domain", domPriority, []string{name}, nil)
			addr := selectionRule("addr", 10, nil, []string{"192.0.2.0/24"})
			rs := newRuleSet(t, dom, addr)
			base := &config.RuntimeConfig{}

			domRule, _ := SelectRule(rs, base, name, nil)
			want, wantCfg := SelectRule(rs, base, name, hostAddrs)
			got, gotCfg := SelectRule(rs, base, "", hostAddrs, domRule)

			// The rule set returns copies, so compare by content.
			assert.Equal(t, want.Name, got.Name)
			assert.Equal(t, wantCfg.DNS.HTTPSURL, gotCfg.DNS.HTTPSURL)
		}
	})
}
