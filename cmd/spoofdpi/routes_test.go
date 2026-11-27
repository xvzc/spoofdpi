package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/route"
)

// fakeRouteFinder answers the calls of a routeFinder with fixed results per
// family and records them.
type fakeRouteFinder struct {
	egress4    *route.Egress
	err4       error
	egress6    *route.Egress
	err6       error
	ipv6Egress bool
	calls      []string // family
}

func (f *fakeRouteFinder) finder() routeFinder {
	return routeFinder{
		egress: func(fam netutil.Family) (*route.Egress, error) {
			f.calls = append(f.calls, fam.String())
			if fam == netutil.FamilyV6 {
				return f.egress6, f.err6
			}
			return f.egress4, f.err4
		},
		hasIPv6Egress: func() bool { return f.ipv6Egress },
	}
}

// logLines returns the logs in buf as "level: message" lines.
func logLines(t *testing.T, buf *bytes.Buffer) []string {
	t.Helper()
	var lines []string
	sc := bufio.NewScanner(buf)
	for sc.Scan() {
		var entry struct {
			Level   string `json:"level"`
			Message string `json:"message"`
		}
		require.NoError(t, json.Unmarshal(sc.Bytes(), &entry))
		lines = append(lines, entry.Level+": "+entry.Message)
	}
	return lines
}

// Egresses through an interface with a gateway, a point-to-point
// interface without one, and the tunnel interface of a VPN.
var (
	directEgress = &route.Egress{
		Route: route.Route{
			Family:  netutil.FamilyV4,
			Iface:   net.Interface{Index: 4, Name: "en0"},
			LocalIP: net.IPv4(192, 168, 1, 11).To4(),
			Gateway: net.IPv4(192, 168, 1, 1).To4(),
		},
	}
	pppEgress = &route.Egress{
		Route: route.Route{
			Family:  netutil.FamilyV4,
			Iface:   net.Interface{Index: 9, Name: "ppp0"},
			LocalIP: net.IPv4(100, 64, 0, 2).To4(),
		},
	}
	tunnelEgress = &route.Egress{
		Route: route.Route{
			Family:  netutil.FamilyV4,
			Iface:   net.Interface{Index: 12, Name: "utun4"},
			LocalIP: net.IPv4(10, 8, 0, 2).To4(),
		},
	}
)

// egress6 returns a copy of e as an IPv6 egress.
func egress6(e *route.Egress) *route.Egress {
	c := *e
	c.Route.Family = netutil.FamilyV6
	c.Route.LocalIP = net.ParseIP("2001:db8:1::11")
	if c.Route.Gateway != nil {
		c.Route.Gateway = net.ParseIP("fe80::1")
		c.Route.Zone = c.Route.Iface.Name
	}
	return &c
}

const (
	egressInfo    = "info: egress"
	fallback6Warn = "warn: IPv6 is enabled but no usable IPv6 route was found; running with IPv6 disabled"
	callV4        = "ipv4"
	callV6        = "ipv6"
)

type startupMode string

const (
	proxyNoFakes startupMode = "proxy without fakes"
	proxyFakes   startupMode = "proxy with fakes"
	tunMode      startupMode = "tun"
)

// startupConfig returns the default config in mode, with IPv6 enabled
// when ipv6 is set.
func startupConfig(mode startupMode, ipv6 bool) *config.Config {
	cfg := config.DefaultConfig()
	switch mode {
	case proxyFakes:
		cfg.HTTPS.FakePreflight = 1
	case tunMode:
		cfg.App.Mode = config.AppModeTUN
	}
	if ipv6 {
		cfg.App.IPv6 = true
		cfg.IPv6 = true
		cfg.DNS.QType = config.DNSQueryAll
	}
	return cfg
}

func TestDiscoverEgresses_IPv4Matrix(t *testing.T) {
	type tc struct {
		name      string
		egress    *route.Egress
		mode      startupMode
		wantV4    bool
		wantLogs  []string
		wantCalls []string
	}
	var tcs []tc

	// Without fake packets or TUN mode, no IPv4 egress is discovered.
	// With them, the egress is used whatever its interface is.
	for _, e := range []*route.Egress{directEgress, pppEgress, tunnelEgress} {
		name := e.Route.Iface.Name
		tcs = append(tcs,
			tc{name: name + "/" + string(proxyNoFakes), egress: e, mode: proxyNoFakes},
			tc{
				name:      name + "/" + string(proxyFakes),
				egress:    e,
				mode:      proxyFakes,
				wantV4:    true,
				wantLogs:  []string{egressInfo},
				wantCalls: []string{callV4},
			},
			tc{
				name:      name + "/" + string(tunMode),
				egress:    e,
				mode:      tunMode,
				wantV4:    true,
				wantLogs:  []string{egressInfo},
				wantCalls: []string{callV4},
			},
		)
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			finder := fakeRouteFinder{egress4: tc.egress}
			cfg := startupConfig(tc.mode, false)

			got, err := discoverEgresses(zerolog.New(&buf), cfg, finder.finder())

			require.NoError(t, err)
			if tc.wantV4 {
				assert.Same(t, tc.egress, got.V4)
			} else {
				assert.Nil(t, got.V4)
			}
			assert.Nil(t, got.V6)
			assert.Equal(t, ipv6StayedOn, got.IPv6Off)
			assert.Equal(t, tc.wantLogs, logLines(t, &buf))
			assert.Equal(t, tc.wantCalls, finder.calls)
		})
	}
}

func TestDiscoverEgresses_IPv4Errors(t *testing.T) {
	noRoute := fmt.Errorf(
		"discover egress: route lookup 192.0.2.1: %w",
		route.ErrNoIPv4,
	)
	tcs := []struct {
		name       string
		err        error
		ipv6Egress bool
		wantErr    string
		wantNoV4   bool
	}{
		{
			name:       "no route",
			err:        noRoute,
			ipv6Egress: true,
			wantErr: "fake packets and TUN mode need an IPv4 default route; none found " +
				"(IPv6 route: present). IPv6-only networks are not supported yet; disable " +
				"fake packets and use HTTP or SOCKS5 mode: discover egress: " +
				"route lookup 192.0.2.1: no IPv4 default route",
			wantNoV4: true,
		},
		{
			name: "discovery fails",
			err:  errors.New("discover egress: route lookup 192.0.2.1: permission denied"),
			wantErr: "failed to find default route: discover egress: route lookup 192.0.2.1: " +
				"permission denied; disable fake packets and use HTTP or SOCKS5 mode to run without it",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			finder := fakeRouteFinder{err4: tc.err, ipv6Egress: tc.ipv6Egress}
			cfg := startupConfig(tunMode, false)

			_, err := discoverEgresses(zerolog.Nop(), cfg, finder.finder())

			require.Error(t, err)
			assert.Equal(t, tc.wantErr, err.Error())
			assert.Equal(t, tc.wantNoV4, errors.Is(err, route.ErrNoIPv4))
		})
	}
}

// TestDiscoverEgresses_EgressLine checks the fields of the egress line,
// for a route with a gateway and one without.
func TestDiscoverEgresses_EgressLine(t *testing.T) {
	tcs := []struct {
		name   string
		egress *route.Egress
		want   map[string]string
	}{
		{
			name:   "gateway",
			egress: directEgress,
			want: map[string]string{
				"family":    "ipv4",
				"interface": "en0",
				"gateway":   "192.168.1.1",
				"src":       "192.168.1.11",
				"message":   "egress",
			},
		},
		{
			name:   "no gateway",
			egress: pppEgress,
			want: map[string]string{
				"family":    "ipv4",
				"interface": "ppp0",
				"gateway":   "-",
				"src":       "100.64.0.2",
				"message":   "egress",
			},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			finder := fakeRouteFinder{egress4: tc.egress}

			_, err := discoverEgresses(
				zerolog.New(&buf),
				startupConfig(tunMode, false),
				finder.finder(),
			)

			require.NoError(t, err)
			var entry map[string]string
			require.NoError(t, json.Unmarshal(buf.Bytes(), &entry))
			delete(entry, "level")
			assert.Equal(t, tc.want, entry)
		})
	}
}

func TestDiscoverEgresses_IPv6(t *testing.T) {
	noRoute6 := fmt.Errorf(
		"discover egress: route lookup 2001:db8::1: %w",
		route.ErrNoIPv6,
	)
	eafnosupport := fmt.Errorf(
		"discover egress: route lookup 2001:db8::1: %w",
		syscall.EAFNOSUPPORT,
	)
	tcs := []struct {
		name      string
		mode      startupMode
		ipv6      bool
		egress6   *route.Egress
		err6      error
		wantV6    bool
		wantOff   ipv6OffCause
		wantLogs  []string
		wantCalls []string
	}{
		{
			name:      "direct",
			mode:      proxyNoFakes,
			ipv6:      true,
			egress6:   egress6(directEgress),
			wantV6:    true,
			wantLogs:  []string{egressInfo},
			wantCalls: []string{callV6},
		},
		{
			name:      "no route",
			mode:      proxyNoFakes,
			ipv6:      true,
			err6:      noRoute6,
			wantOff:   ipv6OffNoRoute,
			wantLogs:  []string{fallback6Warn},
			wantCalls: []string{callV6},
		},
		{
			name:      "address family not supported",
			mode:      proxyFakes,
			ipv6:      true,
			err6:      eafnosupport,
			wantOff:   ipv6OffNoRoute,
			wantLogs:  []string{egressInfo, fallback6Warn},
			wantCalls: []string{callV4, callV6},
		},
		{
			name:      "tunnel in tun",
			mode:      tunMode,
			ipv6:      true,
			egress6:   egress6(tunnelEgress),
			wantV6:    true,
			wantLogs:  []string{egressInfo, egressInfo},
			wantCalls: []string{callV4, callV6},
		},
		{
			name:      "tunnel in proxy",
			mode:      proxyNoFakes,
			ipv6:      true,
			egress6:   egress6(tunnelEgress),
			wantV6:    true,
			wantLogs:  []string{egressInfo},
			wantCalls: []string{callV6},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			finder := fakeRouteFinder{
				egress4: directEgress,
				egress6: tc.egress6,
				err6:    tc.err6,
			}
			cfg := startupConfig(tc.mode, tc.ipv6)

			got, err := discoverEgresses(zerolog.New(&buf), cfg, finder.finder())

			assert.Equal(t, tc.wantLogs, logLines(t, &buf))
			assert.Equal(t, tc.wantCalls, finder.calls)
			require.NoError(t, err)
			if tc.wantV6 {
				assert.Same(t, tc.egress6, got.V6)
			} else {
				assert.Nil(t, got.V6)
			}
			assert.Equal(t, tc.wantOff, got.IPv6Off)
			assert.Equal(
				t,
				tc.ipv6 && tc.wantOff == ipv6StayedOn,
				cfg.IPv6Enabled(),
				"IPv6Enabled",
			)
		})
	}
}

// TestDiscoverEgresses_RuleEnablesIPv6 checks that a rule's ipv6 makes the
// proxy modes discover the IPv6 egress, and that the fallback turns IPv6
// off in the whole config, rules included, before the servers read it.
func TestDiscoverEgresses_RuleEnablesIPv6(t *testing.T) {
	cfg := config.DefaultConfig()
	on, off := true, false
	rc := cfg.RuntimeConfig
	rc.IPv6 = true
	rc.DNS.QType = config.DNSQueryAll
	cfg.Rules = []config.Rule{
		{Name: "on", IPv6: &on, Config: rc},
		{Name: "off", IPv6: &off, Config: cfg.RuntimeConfig},
	}
	require.True(t, cfg.IPv6Enabled())
	finder := fakeRouteFinder{err6: route.ErrNoIPv6}

	got, err := discoverEgresses(zerolog.Nop(), cfg, finder.finder())

	require.NoError(t, err)
	assert.Equal(t, ipv6OffNoRoute, got.IPv6Off)
	assert.Equal(t, []string{callV6}, finder.calls)
	assert.False(t, cfg.IPv6Enabled())
	for _, r := range cfg.Rules {
		assert.False(t, r.Config.IPv6, r.Name)
		assert.Equal(t, config.DNSQueryIPv4, r.Config.DNS.QType, r.Name)
	}
	assert.True(t, cfg.Rules[1].IPv4Only(), "a rule with ipv6 = false keeps to IPv4")
}
