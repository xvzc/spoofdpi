package main

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/xvzc/spoofdpi/internal/config"
)

func TestLogTUNNotes(t *testing.T) {
	const (
		bypassWarn = "IPv6 traffic bypasses spoofdpi in TUN mode"
		enableHint = "enable --ipv6 or disable IPv6 on the system"
		noRouteOff = "IPv6 was disabled because no usable IPv6 route was found; " +
			"IPv6 traffic bypasses spoofdpi in TUN mode; " +
			"disable IPv6 on the system to keep it from leaking"
		ignoredInfo = "the rules' ipv6 and the dns settings are ignored in TUN mode"
	)

	tunConfig := func(edit func(cfg *config.Config)) *config.Config {
		cfg := config.DefaultConfig()
		cfg.App.Mode = config.AppModeTUN
		if edit != nil {
			edit(cfg)
		}
		return cfg
	}

	tcs := []struct {
		name          string
		cfg           *config.Config
		hasIPv6Egress bool
		ipv6Off       ipv6OffCause
		want          []string
		notWant       []string
	}{
		{
			name:          "ipv6 disabled for no route, with IPv6 egress",
			cfg:           tunConfig(nil),
			hasIPv6Egress: true,
			ipv6Off:       ipv6OffNoRoute,
			want:          []string{noRouteOff},
			notWant:       []string{enableHint},
		},
		{
			name:    "ipv6 disabled for no route, without IPv6 egress",
			cfg:     tunConfig(nil),
			ipv6Off: ipv6OffNoRoute,
			notWant: []string{noRouteOff, bypassWarn},
		},
		{
			name:          "ipv6 off with IPv6 egress",
			cfg:           tunConfig(nil),
			hasIPv6Egress: true,
			want:          []string{bypassWarn, enableHint},
			notWant:       []string{ignoredInfo, noRouteOff},
		},
		{
			name:          "ipv6 off without IPv6 egress",
			cfg:           tunConfig(nil),
			hasIPv6Egress: false,
			notWant:       []string{bypassWarn, ignoredInfo},
		},
		{
			name: "ipv6 on with IPv6 egress",
			cfg: tunConfig(func(cfg *config.Config) {
				cfg.App.IPv6 = true
			}),
			hasIPv6Egress: true,
			notWant:       []string{bypassWarn, ignoredInfo},
		},
		{
			name: "a rule enabling ipv6 does not count",
			cfg: tunConfig(func(cfg *config.Config) {
				r := config.Rule{Config: cfg.RuntimeConfig, IPv6: lo.ToPtr(true)}
				r.Config.IPv6 = true
				cfg.Rules = []config.Rule{r}
			}),
			hasIPv6Egress: true,
			want:          []string{bypassWarn, ignoredInfo},
		},
		{
			name: "global dns settings",
			cfg: tunConfig(func(cfg *config.Config) {
				cfg.DNS.Mode = config.DNSModeHTTPS
			}),
			want: []string{ignoredInfo},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			logTUNNotes(zerolog.New(&buf), tc.cfg, tc.hasIPv6Egress, tc.ipv6Off)
			for _, s := range tc.want {
				assert.Contains(t, buf.String(), s)
			}
			for _, s := range tc.notWant {
				assert.NotContains(t, buf.String(), s)
			}
		})
	}
}

func TestTUNIgnoresSettings(t *testing.T) {
	withRule := func(edit func(r *config.Rule)) *config.Config {
		cfg := config.DefaultConfig()
		r := config.Rule{Config: cfg.RuntimeConfig}
		edit(&r)
		cfg.Rules = []config.Rule{r}
		return cfg
	}

	tcs := []struct {
		name   string
		cfg    *config.Config
		expect bool
	}{
		{"defaults", config.DefaultConfig(), false},
		{
			"rule inheriting everything",
			withRule(func(r *config.Rule) {}),
			false,
		},
		{
			"rule sets ipv6",
			withRule(func(r *config.Rule) { r.IPv6 = lo.ToPtr(false) }),
			true,
		},
		{
			"rule inherits ipv6",
			withRule(func(r *config.Rule) { r.Config.IPv6 = true }),
			false,
		},
		{
			"rule dns addr",
			withRule(func(r *config.Rule) {
				r.Config.DNS.Addr = net.TCPAddr{IP: net.ParseIP("1.1.1.1"), Port: 53}
			}),
			true,
		},
		{
			"rule dns timeout",
			withRule(func(r *config.Rule) { r.Config.DNS.Timeout = time.Second }),
			true,
		},
		{
			"query type alone",
			withRule(func(r *config.Rule) { r.Config.DNS.QType = config.DNSQueryAll }),
			false,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expect, tunIgnoresSettings(tc.cfg))
		})
	}
}
