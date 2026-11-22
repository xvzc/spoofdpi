package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The removed 'qtype' option is still accepted, with a warning, and has no
// effect: the record types follow the ipv6 option.
func TestDNSQTypeDeprecated(t *testing.T) {
	const warnTOML = "'dns.qtype' is deprecated and ignored; " +
		"set 'ipv6 = true' in [app], or in the rule, to resolve IPv6 addresses"

	t.Run("dns section", func(t *testing.T) {
		cfg, warns := runWithTOML(t, "[dns]\nqtype = \"ipv6\"\n")
		assert.Equal(t, DNSQueryIPv4, cfg.DNS.QType)
		assert.Contains(t, warns, warnTOML)
	})

	t.Run("rule dns section", func(t *testing.T) {
		cfg, warns := runWithTOML(t, `
[[rules]]
name = "r"
match = { domains = ["example.com"] }
dns = { qtype = "all" }
`)
		require.Len(t, cfg.Rules, 1)
		assert.Equal(t, DNSQueryIPv4, cfg.Rules[0].Config.DNS.QType)
		assert.Contains(t, warns, "rule 0: "+warnTOML)
	})

	t.Run("flag", func(t *testing.T) {
		cfg, warns := runWithTOML(t, "", "--dns-qtype", "all")
		assert.Equal(t, DNSQueryIPv4, cfg.DNS.QType)
		assert.Contains(
			t,
			warns,
			"'--dns-qtype' is deprecated and ignored; use '--ipv6' to resolve IPv6 addresses",
		)
	})

	t.Run("flag is hidden", func(t *testing.T) {
		cmd := CreateCommand(nil, "v0.0.0", "commit", "build")
		for _, f := range cmd.VisibleFlags() {
			assert.NotContains(t, f.Names(), "dns-qtype")
		}
	})
}

func TestDNSQueryType_followsIPv6(t *testing.T) {
	const rules = `
[[rules]]
name = "unset"
match = { domains = ["a.example"] }

[[rules]]
name = "on"
match = { domains = ["b.example"] }
ipv6 = true

[[rules]]
name = "off"
match = { domains = ["c.example"] }
ipv6 = false
`

	tcs := []struct {
		name      string
		args      []string
		wantBase  DNSQueryType
		wantRules []DNSQueryType // unset, on, off
	}{
		{
			name:      "ipv6 off",
			wantBase:  DNSQueryIPv4,
			wantRules: []DNSQueryType{DNSQueryIPv4, DNSQueryAll, DNSQueryIPv4},
		},
		{
			name:      "ipv6 on",
			args:      []string{"--ipv6"},
			wantBase:  DNSQueryAll,
			wantRules: []DNSQueryType{DNSQueryAll, DNSQueryAll, DNSQueryIPv4},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			cfg, _ := runWithTOML(t, rules, tc.args...)
			assert.Equal(t, tc.wantBase, cfg.DNS.QType)
			require.Len(t, cfg.Rules, len(tc.wantRules))
			for i, want := range tc.wantRules {
				assert.Equal(t, want, cfg.Rules[i].Config.DNS.QType, cfg.Rules[i].Name)
			}
		})
	}
}
