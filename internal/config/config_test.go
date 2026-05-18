package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_UnmarshalTOML(t *testing.T) {
	tcs := []struct {
		name    string
		input   any
		wantErr bool
		assert  func(t *testing.T, c Config)
	}{
		{
			name: "valid config",
			input: map[string]any{
				"app": map[string]any{
					"listen-addr": "127.0.0.1:9090",
				},
				"dns": map[string]any{
					"addr": "1.1.1.1:53",
				},
				"policy": map[string]any{
					"overrides": []map[string]any{
						{
							"name": "test",
							"match": map[string]any{
								"domains": []any{"example.com"},
							},
							"dns": map[string]any{
								"route": "doh",
							},
						},
					},
				},
			},
			wantErr: false,
			assert: func(t *testing.T, c Config) {
				assert.Equal(t, "127.0.0.1:9090", c.Startup.App.ListenAddr.String())
				assert.Equal(t, "1.1.1.1:53", c.Runtime.DNS.Addr.String())
				// Startup.Rules is populated by Load via resolveRules,
				// not by Config.UnmarshalTOML; see TestResolveRules_*.
			},
		},
		{
			name:    "invalid type",
			input:   "invalid",
			wantErr: true,
		},
		{
			name: "validation error",
			input: map[string]any{
				"app": map[string]any{
					"listen-addr": "invalid-addr",
				},
			},
			wantErr: true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			c := DefaultConfig()
			err := c.UnmarshalTOML(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			require.NoError(t, c.Finalize())
			if tc.assert != nil {
				tc.assert(t, *c)
			}
		})
	}
}

func TestConfig_NeedsPcapTCP(t *testing.T) {
	tcs := []struct {
		name   string
		config Config
		expect bool
	}{
		{
			name: "global https fake count > 0",
			config: Config{
				Runtime: RuntimeConfig{
					HTTPS: HTTPSOptions{FakeCount: uint8(1)},
				},
			},
			expect: true,
		},
		{
			name: "rule https fake count > 0",
			config: Config{
				Startup: StartupConfig{
					Rules: []Rule{
						{
							Config: RuntimeConfig{
								HTTPS: HTTPSOptions{FakeCount: uint8(1)},
							},
						},
					},
				},
			},
			expect: true,
		},
		{
			name: "udp fake count alone is not TCP",
			config: Config{
				Runtime: RuntimeConfig{
					UDP: UDPOptions{FakeCount: uint8(1)},
				},
			},
			expect: false,
		},
		{
			name:   "none",
			config: Config{},
			expect: false,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expect, tc.config.NeedsPcapTCP())
		})
	}
}

func TestConfig_NeedsPcapUDP(t *testing.T) {
	tcs := []struct {
		name   string
		config Config
		expect bool
	}{
		{
			name: "global udp fake count > 0",
			config: Config{
				Runtime: RuntimeConfig{
					UDP: UDPOptions{FakeCount: uint8(1)},
				},
			},
			expect: true,
		},
		{
			name: "rule udp fake count > 0",
			config: Config{
				Startup: StartupConfig{
					Rules: []Rule{
						{
							Config: RuntimeConfig{
								UDP: UDPOptions{FakeCount: uint8(1)},
							},
						},
					},
				},
			},
			expect: true,
		},
		{
			name: "https fake count alone is not UDP",
			config: Config{
				Runtime: RuntimeConfig{
					HTTPS: HTTPSOptions{FakeCount: uint8(1)},
				},
			},
			expect: false,
		},
		{
			name:   "none",
			config: Config{},
			expect: false,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expect, tc.config.NeedsPcapUDP())
		})
	}
}

func TestConfig_Validate_rejectsRuleWithoutMatch(t *testing.T) {
	c := DefaultConfig()
	c.Startup.Rules = []Rule{
		{
			Name:  "no-match",
			Match: nil, // missing match attribute
		},
	}
	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rules[0]")
	assert.Contains(t, err.Error(), "match attribute")
}

func TestConfig_Validate_acceptsValidRule(t *testing.T) {
	c := DefaultConfig()
	c.Startup.Rules = []Rule{
		{
			Name: "ok",
			Match: &MatchAttrs{
				Domains: []string{"example.com"},
			},
		},
	}
	assert.NoError(t, c.Validate())
}

func TestResolveRules_inheritsFromBase(t *testing.T) {
	base := DefaultConfig().Runtime
	base.HTTPS.FakeCount = 5
	base.HTTPS.SplitMode = HTTPSSplitModeChunk
	base.HTTPS.ChunkSize = 99

	raw := []map[string]any{
		{
			"name": "rule1",
			"match": map[string]any{
				"domains": []any{"example.com"},
			},
			"https": map[string]any{
				// Only override fake-count; other HTTPS fields should
				// inherit from the base RuntimeConfig (eager-resolve at load).
				"fake-count": int64(2),
			},
		},
	}

	rules, err := resolveRules(raw, base)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	rule := rules[0]
	assert.Equal(t, "rule1", rule.Name)
	assert.Equal(t, uint8(2), rule.Config.HTTPS.FakeCount, "rule overrides fake-count")
	assert.Equal(
		t, HTTPSSplitModeChunk, rule.Config.HTTPS.SplitMode,
		"rule inherits split-mode from base",
	)
	assert.Equal(
		t,
		uint8(99),
		rule.Config.HTTPS.ChunkSize,
		"rule inherits chunk-size from base",
	)
}

// TestResolveRules_skipNotInheritedFromBase pins the rule that
// https.skip is NEVER inherited from base into a policy override:
// the override starts at skip=false regardless of what the static
// config or CLI set, and only the rule's own TOML can flip it back
// on. This keeps a global https.skip=true from silently turning
// otherwise-tuned override rules into no-ops.
func TestResolveRules_skipNotInheritedFromBase(t *testing.T) {
	tcs := []struct {
		name      string
		baseSkip  bool
		ruleHTTPS map[string]any
		wantSkip  bool
	}{
		{
			name:      "base true, rule omits skip → false",
			baseSkip:  true,
			ruleHTTPS: map[string]any{"chunk-size": int64(8)},
			wantSkip:  false,
		},
		{
			name:      "base true, rule has no https section → false",
			baseSkip:  true,
			ruleHTTPS: nil,
			wantSkip:  false,
		},
		{
			name:      "base true, rule explicitly skip=true → true",
			baseSkip:  true,
			ruleHTTPS: map[string]any{"skip": true},
			wantSkip:  true,
		},
		{
			name:      "base true, rule explicitly skip=false → false",
			baseSkip:  true,
			ruleHTTPS: map[string]any{"skip": false},
			wantSkip:  false,
		},
		{
			name:      "base false, rule omits skip → false",
			baseSkip:  false,
			ruleHTTPS: map[string]any{"chunk-size": int64(8)},
			wantSkip:  false,
		},
		{
			name:      "base false, rule explicitly skip=true → true",
			baseSkip:  false,
			ruleHTTPS: map[string]any{"skip": true},
			wantSkip:  true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			base := DefaultConfig().Runtime
			base.HTTPS.Skip = tc.baseSkip

			item := map[string]any{
				"name":  "r",
				"match": map[string]any{"domains": []any{"example.com"}},
			}
			if tc.ruleHTTPS != nil {
				item["https"] = tc.ruleHTTPS
			}

			rules, err := resolveRules([]map[string]any{item}, base)
			require.NoError(t, err)
			require.Len(t, rules, 1)
			assert.Equal(t, tc.wantSkip, rules[0].Config.HTTPS.Skip)
		})
	}
}
