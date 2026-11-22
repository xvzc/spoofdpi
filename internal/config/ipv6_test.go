package config

import (
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIPv6Option(t *testing.T) {
	const warnExperimental = "'ipv6' is an experimental feature"

	t.Run("off by default", func(t *testing.T) {
		cfg, warns := runWithTOML(t, "")
		assert.False(t, cfg.App.IPv6)
		assert.False(t, cfg.IPv6)
		assert.NotContains(t, warns, warnExperimental)
	})

	t.Run("flag", func(t *testing.T) {
		cfg, warns := runWithTOML(t, "", "--ipv6")
		assert.True(t, cfg.App.IPv6)
		assert.True(t, cfg.IPv6)
		assert.Contains(t, warns, warnExperimental)
	})

	t.Run("app section", func(t *testing.T) {
		cfg, warns := runWithTOML(t, "[app]\nipv6 = true\n")
		assert.True(t, cfg.App.IPv6)
		assert.True(t, cfg.IPv6)
		assert.Contains(t, warns, warnExperimental)
	})

	t.Run("flag wins over the app section", func(t *testing.T) {
		cfg, warns := runWithTOML(t, "[app]\nipv6 = true\n", "--ipv6=false")
		assert.False(t, cfg.App.IPv6)
		assert.False(t, cfg.IPv6)
		assert.NotContains(t, warns, warnExperimental)
	})

	t.Run("non-bool value", func(t *testing.T) {
		_, _, err := runCmd(t, "[app]\nipv6 = \"yes\"\n")
		assert.ErrorContains(t, err, `field "ipv6"`)
	})
}

func TestIPv6Option_Rules(t *testing.T) {
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
		name   string
		global string
		want   []bool // per rule: unset, on, off
	}{
		{"global off", "", []bool{false, true, false}},
		{"global on", "[app]\nipv6 = true\n", []bool{true, true, false}},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			cfg, _ := runWithTOML(t, tc.global+rules)
			require.Len(t, cfg.Rules, len(tc.want))
			for i, want := range tc.want {
				assert.Equal(t, want, cfg.Rules[i].Config.IPv6, cfg.Rules[i].Name)
			}
		})
	}

	t.Run("only a rule's own ipv6 is kept", func(t *testing.T) {
		cfg, _ := runWithTOML(t, rules, "--ipv6")
		require.Len(t, cfg.Rules, 3)
		assert.Nil(t, cfg.Rules[0].IPv6)
		assert.Equal(t, lo.ToPtr(true), cfg.Rules[1].IPv6)
		assert.Equal(t, lo.ToPtr(false), cfg.Rules[2].IPv6)
	})

	t.Run("rule inherits the flag", func(t *testing.T) {
		cfg, _ := runWithTOML(t, rules, "--ipv6")
		require.Len(t, cfg.Rules, 3)
		assert.True(t, cfg.Rules[0].Config.IPv6)
		assert.False(t, cfg.Rules[2].Config.IPv6)
	})

	t.Run("non-bool value", func(t *testing.T) {
		_, _, err := runCmd(t, `
[[rules]]
match = { domains = ["a.example"] }
ipv6 = 1
`)
		assert.ErrorContains(t, err, "rule 0: ipv6")
	})
}

func TestConfig_IPv6Enabled(t *testing.T) {
	ruleWith := func(ipv6 bool) Rule {
		return Rule{Config: RuntimeConfig{IPv6: ipv6}}
	}

	tcs := []struct {
		name   string
		config Config
		expect bool
	}{
		{
			name:   "off",
			config: Config{App: AppOptions{Mode: AppModeHTTP}},
			expect: false,
		},
		{
			name:   "global on",
			config: Config{App: AppOptions{Mode: AppModeHTTP, IPv6: true}},
			expect: true,
		},
		{
			name: "a rule on",
			config: Config{
				App:   AppOptions{Mode: AppModeSOCKS5},
				Rules: []Rule{ruleWith(false), ruleWith(true)},
			},
			expect: true,
		},
		{
			name: "rules off",
			config: Config{
				App:   AppOptions{Mode: AppModeSOCKS5},
				Rules: []Rule{ruleWith(false)},
			},
			expect: false,
		},
		{
			name:   "tun with global on",
			config: Config{App: AppOptions{Mode: AppModeTUN, IPv6: true}},
			expect: true,
		},
		{
			name: "tun ignores the rules",
			config: Config{
				App:   AppOptions{Mode: AppModeTUN},
				Rules: []Rule{ruleWith(true)},
			},
			expect: false,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expect, tc.config.IPv6Enabled())
		})
	}
}

func TestRule_IPv4Only(t *testing.T) {
	tcs := []struct {
		name   string
		rule   *Rule
		expect bool
	}{
		{"nil receiver", nil, false},
		{"inherits", &Rule{Config: RuntimeConfig{IPv6: false}}, false},
		{"sets on", &Rule{IPv6: lo.ToPtr(true)}, false},
		{"sets off", &Rule{IPv6: lo.ToPtr(false)}, true},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expect, tc.rule.IPv4Only())
		})
	}
}
