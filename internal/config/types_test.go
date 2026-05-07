package config

import (
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/xvzc/spoofdpi/internal/proto"
)

// ┌─────────────────┐
// │ GENERAL OPTIONS │
// └─────────────────┘
func TestAppOptions_UnmarshalTOML(t *testing.T) {
	tcs := []struct {
		name    string
		input   any
		wantErr bool
		assert  func(t *testing.T, o AppOptions)
	}{
		{
			name: "valid general options",
			input: map[string]any{
				"log-level":              "debug",
				"no-tui":                 true,
				"auto-configure-network": true,
				"mode":                   "socks5",
			},
			wantErr: false,
			assert: func(t *testing.T, o AppOptions) {
				assert.Equal(t, zerolog.DebugLevel, o.LogLevel)
				assert.True(t, o.NoTUI)
				assert.True(t, o.AutoConfigureNetwork)
				assert.Equal(t, AppModeSOCKS5, o.Mode)
			},
		},
		{
			name:    "invalid type",
			input:   "invalid",
			wantErr: true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			var o AppOptions
			err := o.UnmarshalTOML(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tc.assert != nil {
					tc.assert(t, o)
				}
			}
		})
	}
}

// ┌────────────────┐
// │ SERVER OPTIONS │
// └────────────────┘
func TestConnOptions_UnmarshalTOML(t *testing.T) {
	tcs := []struct {
		name    string
		input   any
		wantErr bool
		assert  func(t *testing.T, o ConnOptions)
	}{
		{
			name: "valid server options",
			input: map[string]any{
				"default-fake-ttl": int64(64),
				"dns-timeout":      int64(1000),
				"tcp-timeout":      int64(1000),
				"udp-idle-timeout": int64(1000),
			},
			wantErr: false,
			assert: func(t *testing.T, o ConnOptions) {
				assert.Equal(t, uint8(64), o.DefaultFakeTTL)
				assert.Equal(t, 1000*time.Millisecond, o.DNSTimeout)
				assert.Equal(t, 1000*time.Millisecond, o.TCPTimeout)
				assert.Equal(t, 1000*time.Millisecond, o.UDPIdleTimeout)
			},
		},
		{
			name:    "invalid type",
			input:   "invalid",
			wantErr: true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			var o ConnOptions
			err := o.UnmarshalTOML(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tc.assert != nil {
					tc.assert(t, o)
				}
			}
		})
	}
}

// ┌─────────────┐
// │ DNS OPTIONS │
// └─────────────┘
func TestDNSOptions_UnmarshalTOML(t *testing.T) {
	tcs := []struct {
		name    string
		input   any
		wantErr bool
		assert  func(t *testing.T, o DNSOptions)
	}{
		{
			name: "valid dns options",
			input: map[string]any{
				"mode":      "https",
				"addr":      "8.8.8.8:53",
				"https-url": "https://dns.google/dns-query",
				"qtype":     "ipv4",
				"cache":     true,
			},
			wantErr: false,
			assert: func(t *testing.T, o DNSOptions) {
				assert.Equal(t, DNSModeHTTPS, o.Mode)
				assert.Equal(t, "8.8.8.8:53", o.Addr.String())
				assert.Equal(t, "https://dns.google/dns-query", o.HTTPSURL)
				assert.Equal(t, DNSQueryIPv4, o.QType)
				assert.True(t, o.Cache)
			},
		},
		{
			name:    "invalid type",
			input:   "invalid",
			wantErr: true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			var o DNSOptions
			err := o.UnmarshalTOML(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tc.assert != nil {
					tc.assert(t, o)
				}
			}
		})
	}
}

// ┌───────────────┐
// │ HTTPS OPTIONS │
// └───────────────┘
func TestHTTPSOptions_UnmarshalTOML(t *testing.T) {
	tcs := []struct {
		name    string
		input   any
		wantErr bool
		assert  func(t *testing.T, o HTTPSOptions)
	}{
		{
			name: "valid https options",
			input: map[string]any{
				"disorder":    true,
				"fake-count":  int64(5),
				"fake-packet": []any{int64(0x01), int64(0x02)},
				"split-mode":  "chunk",
				"chunk-size":  int64(20),
				"skip":        true,
			},
			wantErr: false,
			assert: func(t *testing.T, o HTTPSOptions) {
				assert.True(t, o.Disorder)
				assert.Equal(t, uint8(5), o.FakeCount)
				assert.Equal(t, []byte{0x01, 0x02}, o.FakePacket.Raw())
				assert.Equal(t, HTTPSSplitModeChunk, o.SplitMode)
				assert.Equal(t, uint8(20), o.ChunkSize)
				assert.True(t, o.Skip)
			},
		},
		{
			name:    "invalid type",
			input:   "invalid",
			wantErr: true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			var o HTTPSOptions
			err := o.UnmarshalTOML(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tc.assert != nil {
					tc.assert(t, o)
				}
			}
		})
	}
}

// ┌─────────────┐
// │ MATCH ATTRS │
// └─────────────┘
func TestMatchAttrs_UnmarshalTOML(t *testing.T) {
	tcs := []struct {
		name    string
		input   any
		wantErr bool
		assert  func(t *testing.T, m MatchAttrs)
	}{
		{
			name: "valid domain",
			input: map[string]any{
				"domain": []any{"example.com"},
			},
			wantErr: false,
			assert: func(t *testing.T, m MatchAttrs) {
				assert.Len(t, m.Domains, 1)
				assert.Equal(t, "example.com", m.Domains[0])
				assert.Empty(t, m.CIDRs)
			},
		},
		{
			name: "valid cidrs",
			input: map[string]any{
				"cidrs": []any{"192.168.1.0/24", "10.0.0.0/8"},
			},
			wantErr: false,
			assert: func(t *testing.T, m MatchAttrs) {
				assert.Len(t, m.CIDRs, 2)
				assert.Equal(t, "192.168.1.0/24", m.CIDRs[0])
				assert.Equal(t, "10.0.0.0/8", m.CIDRs[1])
			},
		},
		{
			name: "invalid cidr",
			input: map[string]any{
				"cidrs": []any{"not-a-cidr"},
			},
			wantErr: true,
		},
		{
			name:    "invalid type",
			input:   "invalid",
			wantErr: true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			var m MatchAttrs
			err := m.UnmarshalTOML(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			if tc.assert != nil {
				tc.assert(t, m)
			}
		})
	}
}

// ┌──────┐
// │ RULE │
// └──────┘
func TestRule_UnmarshalTOML(t *testing.T) {
	tcs := []struct {
		name    string
		input   any
		wantErr bool
		assert  func(t *testing.T, r Rule)
	}{
		{
			name: "valid rule",
			input: map[string]any{
				"name": "rule1",
				"match": map[string]any{
					"domain": []any{"example.com"},
				},
				"block": true,
			},
			wantErr: false,
			assert: func(t *testing.T, r Rule) {
				assert.Equal(t, "rule1", r.Name)
				assert.Equal(t, "example.com", r.Match.Domains[0])
				assert.True(t, r.Block)
			},
		},
		{
			name: "ignores runtime sections",
			input: map[string]any{
				"name": "rule2",
				"connection": map[string]any{
					"tcp-timeout": int64(500),
				},
			},
			wantErr: false,
			assert: func(t *testing.T, r Rule) {
				assert.Equal(t, "rule2", r.Name)
				// Rule.UnmarshalTOML deliberately ignores the config
				// section keys (dns/https/udp/connection); resolveRules
				// in load.go applies them on top of the base RuntimeConfig.
				assert.Equal(t, time.Duration(0), r.Config.Conn.TCPTimeout)
			},
		},
		{
			name:    "invalid type",
			input:   "invalid",
			wantErr: true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			var r Rule
			err := r.UnmarshalTOML(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tc.assert != nil {
					tc.assert(t, r)
				}
			}
		})
	}
}

func TestSegmentPlan_UnmarshalTOML(t *testing.T) {
	t.Run("valid segment head", func(t *testing.T) {
		input := `
from = "head"
at = 10
lazy = true
noise = 1
`
		var s SegmentPlan
		err := toml.Unmarshal([]byte(input), &s)
		assert.NoError(t, err)
		assert.Equal(t, SegmentFromHead, s.From)
		assert.Equal(t, 10, s.At)
		assert.True(t, s.Lazy)
		assert.Equal(t, 1, s.Noise)
	})

	t.Run("valid segment sni", func(t *testing.T) {
		input := `
from = "sni"
at = -5
`
		var s SegmentPlan
		err := toml.Unmarshal([]byte(input), &s)
		assert.NoError(t, err)
		assert.Equal(t, SegmentFromSNI, s.From)
		assert.Equal(t, -5, s.At)
	})

	t.Run("missing required field from", func(t *testing.T) {
		input := `
at = 5
`
		var s SegmentPlan
		err := toml.Unmarshal([]byte(input), &s)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "field 'from' is required")
	})

	t.Run("missing required field at", func(t *testing.T) {
		input := `
from = "head"
`
		var s SegmentPlan
		err := toml.Unmarshal([]byte(input), &s)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "field 'at' is required")
	})

	t.Run("invalid from value", func(t *testing.T) {
		input := `
from = "invalid"
at = 5
`
		var s SegmentPlan
		err := toml.Unmarshal([]byte(input), &s)
		assert.Error(t, err)
	})
}

func TestHTTPSOptions_CustomSegmentPlans(t *testing.T) {
	t.Run("valid custom config", func(t *testing.T) {
		input := `
split-mode = "custom"
custom-segments = [
	{ from = "head", at = 2 },
	{ from = "sni", at = 0 }
]
`
		var opts HTTPSOptions
		err := toml.Unmarshal([]byte(input), &opts)
		assert.NoError(t, err)
		assert.Equal(t, HTTPSSplitModeCustom, opts.SplitMode)
		assert.Len(t, opts.CustomSegmentPlans, 2)
		assert.Equal(t, SegmentFromHead, opts.CustomSegmentPlans[0].From)
		assert.Equal(t, 2, opts.CustomSegmentPlans[0].At)
	})

	t.Run("missing custom segments", func(t *testing.T) {
		input := `
split-mode = "custom"
`
		var opts HTTPSOptions
		err := toml.Unmarshal([]byte(input), &opts)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "custom-segments must be provided")
	})
}

// ┌──────────────────┐
// │ MARSHAL JSON     │
// └──────────────────┘

func TestEnums_MarshalText_StringForms(t *testing.T) {
	tcs := []struct {
		name string
		in   any
		want string
	}{
		{"DNSMode udp", DNSModeUDP, `"udp"`},
		{"DNSMode https", DNSModeHTTPS, `"https"`},
		{"DNSQuery ipv4", DNSQueryIPv4, `"ipv4"`},
		{"HTTPSSplitMode chunk", HTTPSSplitModeChunk, `"chunk"`},
		{"AppMode socks5", AppModeSOCKS5, `"socks5"`},
		{"SegmentFrom sni", SegmentFromSNI, `"sni"`},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(tc.in)
			assert.NoError(t, err)
			assert.Equal(t, tc.want, string(b))
		})
	}
}

func TestConnOptions_MarshalJSON_durationsAsString(t *testing.T) {
	o := ConnOptions{
		DefaultFakeTTL: 8,
		DNSTimeout:     5000 * time.Millisecond,
		TCPTimeout:     10000 * time.Millisecond,
		UDPIdleTimeout: 25000 * time.Millisecond,
	}
	b, err := json.Marshal(o)
	assert.NoError(t, err)
	const want = `{"default-fake-ttl":8,"dns-timeout":"5s",` +
		`"tcp-timeout":"10s","udp-idle-timeout":"25s"}`
	assert.JSONEq(t, want, string(b))
}

func TestDNSOptions_MarshalJSON_addrAsString(t *testing.T) {
	o := DNSOptions{
		Mode:     DNSModeHTTPS,
		Addr:     net.TCPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53},
		HTTPSURL: "https://dns.google/dns-query",
		QType:    DNSQueryIPv4,
		Cache:    true,
	}
	b, err := json.Marshal(o)
	assert.NoError(t, err)
	const want = `{"mode":"https","addr":"8.8.8.8:53",` +
		`"https-url":"https://dns.google/dns-query",` +
		`"qtype":"ipv4","cache":true}`
	assert.JSONEq(t, want, string(b))
}

func TestHTTPSOptions_MarshalJSON_omitsFakePacketBytes(t *testing.T) {
	o := HTTPSOptions{
		Disorder:   false,
		FakeCount:  2,
		FakePacket: proto.NewFakeTLSMessage([]byte{0x01, 0x02, 0x03}),
		SplitMode:  HTTPSSplitModeChunk,
		ChunkSize:  8,
		Skip:       false,
	}
	b, err := json.Marshal(o)
	assert.NoError(t, err)
	got := string(b)
	assert.NotContains(t, got, "fake-packet\":")
	assert.Contains(t, got, `"fake-packet-len":3`)
	assert.Contains(t, got, `"split-mode":"chunk"`)
}

func TestUDPOptions_UnmarshalTOML(t *testing.T) {
	tcs := []struct {
		name    string
		input   any
		wantErr bool
		assert  func(t *testing.T, o UDPOptions)
	}{
		{
			name: "valid udp options",
			input: map[string]any{
				"skip":        true,
				"fake-count":  int64(3),
				"fake-packet": []any{int64(0xAA), int64(0xBB)},
			},
			wantErr: false,
			assert: func(t *testing.T, o UDPOptions) {
				assert.True(t, o.Skip)
				assert.Equal(t, 3, o.FakeCount)
				assert.Equal(t, []byte{0xAA, 0xBB}, o.FakePacket)
			},
		},
		{
			name:    "invalid type",
			input:   "invalid",
			wantErr: true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			var o UDPOptions
			err := o.UnmarshalTOML(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tc.assert != nil {
					tc.assert(t, o)
				}
			}
		})
	}
}

func TestUDPOptions_MarshalJSON_omitsFakePacketBytes(t *testing.T) {
	o := UDPOptions{
		FakeCount:  0,
		FakePacket: make([]byte, 64),
	}
	b, err := json.Marshal(o)
	assert.NoError(t, err)
	got := string(b)
	assert.NotContains(t, got, "fake-packet\":")
	assert.Contains(t, got, `"fake-packet-len":64`)
}

func TestRule_JSON_includesBlockAndConfig(t *testing.T) {
	cfg := DefaultConfig()
	rCfg := cfg.Runtime
	rCfg.HTTPS.SplitMode = HTTPSSplitModeChunk
	rCfg.HTTPS.ChunkSize = 8

	rule := &Rule{
		Name:     "blk",
		Priority: 50,
		Block:    true,
		Match: &MatchAttrs{
			Domains: []string{"example.com"},
		},
		Config: rCfg,
	}

	got := string(rule.JSON())
	assert.Contains(t, got, `"name":"blk"`)
	assert.Contains(t, got, `"priority":50`)
	assert.Contains(t, got, `"block":true`)
	assert.Contains(t, got, `"match":{"domains":"1 items"}`)
	assert.Contains(t, got, `"config":`)
	assert.Contains(t, got, `"split-mode":"chunk"`)
	assert.Contains(t, got, `"chunk-size":8`)
	// The previously-broken short tags should be gone.
	assert.NotContains(t, got, "qt:omitempty")
	assert.NotContains(t, got, "ca:omitempty")
}

func TestMatchAttrs_MarshalJSON_countsOnly(t *testing.T) {
	tcs := []struct {
		name string
		in   MatchAttrs
		want string
	}{
		{
			name: "domains only",
			in:   MatchAttrs{Domains: []string{"a.com", "b.com", "c.com"}},
			want: `{"domains":"3 items"}`,
		},
		{
			name: "cidrs only",
			in:   MatchAttrs{CIDRs: []string{"10.0.0.0/8", "192.168.0.0/16"}},
			want: `{"cidrs":"2 items"}`,
		},
		{
			name: "both",
			in: MatchAttrs{
				Domains: []string{"a.com"},
				CIDRs:   []string{"10.0.0.0/8"},
			},
			want: `{"domains":"1 items","cidrs":"1 items"}`,
		},
		{
			name: "empty",
			in:   MatchAttrs{},
			want: `{}`,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(tc.in)
			assert.NoError(t, err)
			assert.JSONEq(t, tc.want, string(b))
		})
	}
}

func TestHTTPSOptions_MarshalJSON_customSegmentsAsCount(t *testing.T) {
	o := HTTPSOptions{
		SplitMode: HTTPSSplitModeCustom,
		ChunkSize: 8,
		CustomSegmentPlans: []SegmentPlan{
			{From: SegmentFromHead, At: 1},
			{From: SegmentFromHead, At: 3},
			{From: SegmentFromSNI, At: 4},
		},
	}
	b, err := json.Marshal(o)
	assert.NoError(t, err)
	got := string(b)
	assert.Contains(t, got, `"custom-segments":"3 items"`)
	// Individual plan entries must NOT appear.
	assert.NotContains(t, got, `"At":`)
	assert.NotContains(t, got, `"From":`)
}
