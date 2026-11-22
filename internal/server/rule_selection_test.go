package server

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/rule"
)

// fakeResolver answers every lookup with addrs and err, and records the
// lookups.
type fakeResolver struct {
	addrs []netip.Addr
	err   error

	lookups []fakeLookup
}

type fakeLookup struct {
	opts   *config.DNSOptions
	domain string
}

func (r *fakeResolver) Resolve(
	_ context.Context,
	opts *config.DNSOptions,
	domain string,
) ([]netip.Addr, error) {
	r.lookups = append(r.lookups, fakeLookup{opts: opts, domain: domain})
	return r.addrs, r.err
}

// selectionRule returns a rule whose DNS options are tagged with its name.
func selectionRule(
	name string,
	priority uint16,
	block bool,
	domains, cidrs []string,
) *config.Rule {
	r := &config.Rule{
		Name:     name,
		Priority: priority,
		Block:    block,
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

func TestSelectRule(t *testing.T) {
	const name = "example.com"

	domain := func(priority uint16) *config.Rule {
		return selectionRule("domain", priority, false, []string{name}, nil)
	}
	addr := func(priority uint16) *config.Rule {
		return selectionRule("addr", priority, false, nil, []string{"192.0.2.0/24"})
	}

	tcs := []struct {
		name     string
		rules    []*config.Rule
		host     string
		addrs    []net.IP
		resolved []netip.Addr

		// wantLookupOpts is the HTTPSURL tag of the DNS options of the
		// lookup: "base", a rule's name, or "" for no lookup.
		wantLookupOpts string
		wantRule       string // "" for no rule
		wantAddrs      []net.IP
	}{
		{
			name:           "name without a rule is resolved with the base options",
			host:           name,
			resolved:       []netip.Addr{netip.MustParseAddr("198.51.100.1")},
			wantLookupOpts: "base",
			wantAddrs:      ips("198.51.100.1"),
		},
		{
			name:           "name is resolved with its domain rule's options",
			rules:          []*config.Rule{domain(10)},
			host:           name,
			resolved:       []netip.Addr{netip.MustParseAddr("198.51.100.1")},
			wantLookupOpts: "domain",
			wantRule:       "domain",
			wantAddrs:      ips("198.51.100.1"),
		},
		{
			name:           "address rule does not set the lookup options",
			rules:          []*config.Rule{addr(10)},
			host:           name,
			resolved:       []netip.Addr{netip.MustParseAddr("192.0.2.1")},
			wantLookupOpts: "base",
			wantRule:       "addr",
			wantAddrs:      ips("192.0.2.1"),
		},
		{
			name:           "higher-priority domain rule wins",
			rules:          []*config.Rule{domain(20), addr(10)},
			host:           name,
			resolved:       []netip.Addr{netip.MustParseAddr("192.0.2.1")},
			wantLookupOpts: "domain",
			wantRule:       "domain",
			wantAddrs:      ips("192.0.2.1"),
		},
		{
			name:           "higher-priority address rule wins",
			rules:          []*config.Rule{domain(10), addr(20)},
			host:           name,
			resolved:       []netip.Addr{netip.MustParseAddr("192.0.2.1")},
			wantLookupOpts: "domain",
			wantRule:       "addr",
			wantAddrs:      ips("192.0.2.1"),
		},
		{
			name:           "address rule wins a tie",
			rules:          []*config.Rule{domain(10), addr(10)},
			host:           name,
			resolved:       []netip.Addr{netip.MustParseAddr("192.0.2.1")},
			wantLookupOpts: "domain",
			wantRule:       "addr",
			wantAddrs:      ips("192.0.2.1"),
		},
		{
			name:  "any resolved address matches",
			rules: []*config.Rule{addr(10)},
			host:  name,
			resolved: []netip.Addr{
				netip.MustParseAddr("198.51.100.1"),
				netip.MustParseAddr("192.0.2.1"),
			},
			wantLookupOpts: "base",
			wantRule:       "addr",
			wantAddrs:      ips("198.51.100.1", "192.0.2.1"),
		},
		{
			name:      "name with addresses is not resolved",
			rules:     []*config.Rule{domain(20), addr(10)},
			host:      name,
			addrs:     ips("192.0.2.1"),
			wantRule:  "domain",
			wantAddrs: ips("192.0.2.1"),
		},
		{
			name:      "addresses only",
			rules:     []*config.Rule{domain(20), addr(10)},
			addrs:     ips("192.0.2.1"),
			wantRule:  "addr",
			wantAddrs: ips("192.0.2.1"),
		},
		{
			name:      "no rule matches the addresses",
			rules:     []*config.Rule{addr(10)},
			addrs:     ips("198.51.100.1"),
			wantAddrs: ips("198.51.100.1"),
		},
		{
			name: "ip literal name is the address and not a domain name",
			rules: []*config.Rule{
				selectionRule("literal", 20, false, []string{"192.0.2.1"}, nil),
				addr(10),
			},
			host:      "192.0.2.1",
			wantRule:  "addr",
			wantAddrs: ips("192.0.2.1"),
		},
		{
			name:      "ip literal name does not replace the addresses",
			host:      "192.0.2.1",
			addrs:     ips("198.51.100.1"),
			wantAddrs: ips("198.51.100.1"),
		},
		{
			name:           "empty lookup result is not an error",
			rules:          []*config.Rule{domain(10), addr(20)},
			host:           name,
			resolved:       []netip.Addr{},
			wantLookupOpts: "domain",
			wantRule:       "domain",
			wantAddrs:      []net.IP{},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			rs := rule.NewRuleSet()
			for _, r := range tc.rules {
				require.NoError(t, rs.Add(r))
			}
			base := &config.RuntimeConfig{}
			base.DNS.HTTPSURL = "base"
			resolver := &fakeResolver{addrs: tc.resolved}

			sel, err := SelectRule(
				context.Background(), rs, resolver, base, tc.host, tc.addrs,
			)
			require.NoError(t, err)

			if tc.wantLookupOpts == "" {
				assert.Empty(t, resolver.lookups)
			} else if assert.Len(t, resolver.lookups, 1) {
				assert.Equal(t, tc.host, resolver.lookups[0].domain)
				assert.Equal(t, tc.wantLookupOpts, resolver.lookups[0].opts.HTTPSURL)
				if tc.wantLookupOpts == "base" {
					assert.Same(t, &base.DNS, resolver.lookups[0].opts)
				}
			}

			if tc.wantRule == "" {
				assert.Nil(t, sel.Rule)
				assert.Same(t, base, sel.Config)
			} else if assert.NotNil(t, sel.Rule) {
				assert.Equal(t, tc.wantRule, sel.Rule.Name)
				assert.Same(t, &sel.Rule.Config, sel.Config)
			}

			assert.Equal(t, len(tc.wantAddrs), len(sel.Addrs))
			for i := range tc.wantAddrs {
				assert.True(t, tc.wantAddrs[i].Equal(sel.Addrs[i]),
					"addr %d: got %s, want %s", i, sel.Addrs[i], tc.wantAddrs[i])
			}
		})
	}
}

func TestSelectRule_Blocked(t *testing.T) {
	rs := rule.NewRuleSet()
	require.NoError(t, rs.Add(
		selectionRule("block", 10, true, nil, []string{"192.0.2.0/24"}),
	))
	require.NoError(t, rs.Add(
		selectionRule("allow", 10, false, nil, []string{"198.51.100.0/24"}),
	))
	base := &config.RuntimeConfig{}

	tcs := []struct {
		name string
		addr string
		want bool
	}{
		{"blocking rule", "192.0.2.1", true},
		{"allowing rule", "198.51.100.1", false},
		{"no rule", "203.0.113.1", false},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			sel, err := SelectRule(
				context.Background(), rs, nil, base, "", ips(tc.addr),
			)
			require.NoError(t, err)
			assert.Equal(t, tc.want, sel.Blocked())
		})
	}
}

func TestSelectRule_NilRuleSet(t *testing.T) {
	base := &config.RuntimeConfig{}
	resolver := &fakeResolver{addrs: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}

	sel, err := SelectRule(
		context.Background(), nil, resolver, base, "example.com", nil,
	)
	require.NoError(t, err)

	assert.Nil(t, sel.Rule)
	assert.Same(t, base, sel.Config)
	assert.False(t, sel.Blocked())
	if assert.Len(t, resolver.lookups, 1) {
		assert.Same(t, &base.DNS, resolver.lookups[0].opts)
	}
	assert.Equal(t, ips("192.0.2.1")[0].To4(), sel.Addrs[0].To4())
}

func TestSelectRule_ResolverError(t *testing.T) {
	errLookup := errors.New("lookup failed")
	resolver := &fakeResolver{err: errLookup}

	_, err := SelectRule(
		context.Background(),
		rule.NewRuleSet(),
		resolver,
		&config.RuntimeConfig{},
		"example.com",
		nil,
	)

	assert.Same(t, errLookup, err)
}

func TestSelectRule_NoNameOrAddress(t *testing.T) {
	resolver := &fakeResolver{}

	for _, host := range []string{"", "::"} {
		t.Run(host, func(t *testing.T) {
			_, err := SelectRule(
				context.Background(),
				rule.NewRuleSet(),
				resolver,
				&config.RuntimeConfig{},
				host,
				nil,
			)
			if host == "" {
				assert.Error(t, err)
			} else {
				// An IP literal name is an address.
				assert.NoError(t, err)
			}
		})
	}
	assert.Empty(t, resolver.lookups)
}
