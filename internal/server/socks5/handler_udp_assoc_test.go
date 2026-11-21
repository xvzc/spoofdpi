package socks5

import (
	"net"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/rule"
)

// udpRule returns a rule whose config is tagged by its UDP fake count.
func udpRule(
	name string,
	priority uint16,
	domains, cidrs []string,
	fakePreflight uint8,
) *config.Rule {
	r := &config.Rule{
		Name:     name,
		Priority: priority,
		Match:    &config.MatchAttrs{Domains: domains, CIDRs: cidrs},
	}
	r.Config.UDP.FakePreflight = fakePreflight
	return r
}

func newTestUdpAssociateHandler(
	t *testing.T,
	rules ...*config.Rule,
) *UdpAssociateHandler {
	t.Helper()

	rs := rule.NewRuleSet()
	for _, r := range rules {
		require.NoError(t, rs.Add(r))
	}

	base := &config.RuntimeConfig{}
	base.UDP.FakePreflight = 1

	return NewUdpAssociateHandler(zerolog.Nop(), nil, nil, rs, base)
}

func TestUdpAssociateHandler_DestinationConfig(t *testing.T) {
	h := newTestUdpAssociateHandler(
		t,
		udpRule("addr", 10, nil, []string{"203.0.113.0/24"}, 2),
		udpRule("domain", 20, []string{"example.com"}, nil, 3),
		udpRule("low domain", 5, []string{"low.example.org"}, nil, 4),
	)

	tcs := []struct {
		name string
		host string
		addr string
		want uint8
	}{
		{"address rule matches", "203.0.113.7", "203.0.113.7", 2},
		{"no rule matches", "198.51.100.7", "198.51.100.7", 1},
		{"domain rule matches", "example.com", "198.51.100.7", 3},
		{"higher-priority domain beats address", "example.com", "203.0.113.7", 3},
		{"higher-priority address beats domain", "low.example.org", "203.0.113.7", 2},
		{"unmatched domain falls back to base", "other.com", "198.51.100.7", 1},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			cfg := h.destinationConfig(zerolog.Nop(), tc.host, net.ParseIP(tc.addr))
			assert.Equal(t, tc.want, cfg.UDP.FakePreflight)
		})
	}
}

func TestUdpAssociateHandler_DestinationConfig_PerDestination(t *testing.T) {
	h := newTestUdpAssociateHandler(
		t,
		udpRule("a", 10, nil, []string{"203.0.113.0/24"}, 2),
		udpRule("b", 10, nil, []string{"198.51.100.0/24"}, 3),
	)

	// One association talks to several destinations; each gets its own config.
	a := h.destinationConfig(zerolog.Nop(), "203.0.113.7", net.ParseIP("203.0.113.7"))
	b := h.destinationConfig(zerolog.Nop(), "198.51.100.7", net.ParseIP("198.51.100.7"))
	none := h.destinationConfig(zerolog.Nop(), "192.0.2.7", net.ParseIP("192.0.2.7"))

	assert.Equal(t, uint8(2), a.UDP.FakePreflight)
	assert.Equal(t, uint8(3), b.UDP.FakePreflight)
	assert.Same(t, h.cfg, none)
}

func TestUdpAssociateHandler_DestinationConfig_NoRuleSet(t *testing.T) {
	base := &config.RuntimeConfig{}
	h := NewUdpAssociateHandler(zerolog.Nop(), nil, nil, nil, base)

	cfg := h.destinationConfig(zerolog.Nop(), "203.0.113.7", net.ParseIP("203.0.113.7"))

	assert.Same(t, base, cfg)
}
