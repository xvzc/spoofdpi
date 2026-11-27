package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/desync"
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

// Egresses of each class, as route.ClassifyEgress explains them.
var (
	directEgress = &route.Egress{
		Route: route.Route{
			Family:  netutil.FamilyV4,
			Iface:   net.Interface{Index: 4, Name: "en0"},
			LocalIP: net.IPv4(192, 168, 1, 11).To4(),
			Gateway: net.IPv4(192, 168, 1, 1).To4(),
		},
		Link: route.LinkInfo{
			Index:  4,
			Name:   "en0",
			Kind:   route.LinkPhysical,
			Detail: "IFT_ETHER",
		},
		Class:  route.EgressDirect,
		Reason: "physical link en0 (IFT_ETHER)",
	}
	uplinkEgress = &route.Egress{
		Route: route.Route{
			Family:  netutil.FamilyV4,
			Iface:   net.Interface{Index: 9, Name: "ppp0"},
			LocalIP: net.IPv4(100, 64, 0, 2).To4(),
		},
		Link: route.LinkInfo{
			Index:  9,
			Name:   "ppp0",
			Kind:   route.LinkPPP,
			Detail: "IFT_PPP",
		},
		Class:  route.EgressUplink,
		Reason: "ppp link ppp0 (IFT_PPP) is the only default route",
	}
	vpnEgress = &route.Egress{
		Route: route.Route{
			Family:  netutil.FamilyV4,
			Iface:   net.Interface{Index: 12, Name: "utun4"},
			LocalIP: net.IPv4(10, 8, 0, 2).To4(),
		},
		Link: route.LinkInfo{
			Index:  12,
			Name:   "utun4",
			Kind:   route.LinkVPN,
			Detail: "utun",
		},
		Class:  route.EgressVPN,
		Reason: "VPN link utun4 (utun)",
	}
	unknownEgress = &route.Egress{
		Route: route.Route{
			Family:  netutil.FamilyV4,
			Iface:   net.Interface{Index: 13, Name: "tun0"},
			LocalIP: net.IPv4(10, 9, 0, 2).To4(),
		},
		Link: route.LinkInfo{
			Index: 13, Name: "tun0", Kind: route.LinkUnknown, Detail: "IFT_OTHER p2p",
		},
		Class:  route.EgressUnknown,
		Reason: "cannot tell whether tun0 (IFT_OTHER p2p) is a VPN",
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
	unknownWarn   = "warn: cannot tell whether tun0 (IFT_OTHER p2p) is a VPN; proceeding as if it were not; fake packets and TUN mode do not work through a full-tunnel VPN, so if it is one, disconnect it, or disable fake packets and use HTTP or SOCKS5 mode"
	vpnFakesWarn  = "warn: a full-tunnel VPN (VPN link utun4 (utun)) carries the traffic; fake packets are disabled"
	vpnFakesOff   = "fake packets are off for ipv4: a full-tunnel VPN (VPN link utun4 (utun)) carries the traffic"
	vpnTUNErr     = "TUN mode cannot run while a full-tunnel VPN carries the traffic (VPN link utun4 (utun)); disconnect the VPN or use the HTTP or SOCKS5 mode"
	fakesV6Off    = "fake packets are off for ipv6: IPv6 fakes are not supported yet"
	fallback6Warn = "warn: IPv6 is enabled but no usable IPv6 route was found; running with IPv6 disabled"
	vpnTUN6Warn   = "warn: a full-tunnel VPN (VPN link utun4 (utun)) carries IPv6; running with IPv6 disabled"
	vpnProxy6Info = "info: IPv6 goes through a full-tunnel VPN (VPN link utun4 (utun))"
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
		name        string
		egress      *route.Egress
		mode        startupMode
		wantErr     string
		wantV4      bool
		wantFakesV4 string
		wantLogs    []string
		wantCalls   []string
	}
	var tcs []tc

	// Without fake packets or TUN mode, no IPv4 egress is discovered.
	for _, e := range []*route.Egress{directEgress, uplinkEgress, vpnEgress, unknownEgress} {
		tcs = append(tcs, tc{
			name:   e.Class.String() + "/" + string(proxyNoFakes),
			egress: e,
			mode:   proxyNoFakes,
		})
	}

	tcs = append(tcs,
		// direct
		tc{
			name:      "direct/proxy with fakes",
			egress:    directEgress,
			mode:      proxyFakes,
			wantV4:    true,
			wantLogs:  []string{egressInfo},
			wantCalls: []string{callV4},
		},
		tc{
			name: "direct/tun", egress: directEgress, mode: tunMode,
			wantV4: true, wantLogs: []string{egressInfo}, wantCalls: []string{callV4},
		},
		// uplink: a point-to-point default route without a gateway works
		tc{
			name:      "uplink/proxy with fakes",
			egress:    uplinkEgress,
			mode:      proxyFakes,
			wantV4:    true,
			wantLogs:  []string{egressInfo},
			wantCalls: []string{callV4},
		},
		tc{
			name: "uplink/tun", egress: uplinkEgress, mode: tunMode,
			wantV4: true, wantLogs: []string{egressInfo}, wantCalls: []string{callV4},
		},
		// vpn
		tc{
			name: "vpn/proxy with fakes", egress: vpnEgress, mode: proxyFakes,
			wantV4: true, wantFakesV4: vpnFakesOff,
			wantLogs:  []string{egressInfo, vpnFakesWarn},
			wantCalls: []string{callV4},
		},
		tc{
			name: "vpn/tun", egress: vpnEgress, mode: tunMode,
			wantErr:   vpnTUNErr,
			wantLogs:  []string{egressInfo},
			wantCalls: []string{callV4},
		},
		// unknown: warn and proceed
		tc{
			name:      "unknown/proxy with fakes",
			egress:    unknownEgress,
			mode:      proxyFakes,
			wantV4:    true,
			wantLogs:  []string{egressInfo, unknownWarn},
			wantCalls: []string{callV4},
		},
		tc{
			name:      "unknown/tun",
			egress:    unknownEgress,
			mode:      tunMode,
			wantV4:    true,
			wantLogs:  []string{egressInfo, unknownWarn},
			wantCalls: []string{callV4},
		},
	)

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			finder := fakeRouteFinder{egress4: tc.egress}
			cfg := startupConfig(tc.mode, false)

			got, err := discoverEgresses(zerolog.New(&buf), cfg, finder.finder())

			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Equal(t, tc.wantErr, err.Error())
			} else {
				require.NoError(t, err)
				if tc.wantV4 {
					assert.Same(t, tc.egress, got.V4)
				} else {
					assert.Nil(t, got.V4)
				}
				if tc.wantFakesV4 == "" {
					assert.NoError(t, got.FakesV4)
				} else {
					assert.EqualError(t, got.FakesV4, tc.wantFakesV4)
					assert.Equal(t, &desync.FakesOffError{
						Family:    netutil.FamilyV4,
						Kind:      desync.FakesOffVPNAtStartup,
						Interface: "utun4",
						Reason:    "a full-tunnel VPN (VPN link utun4 (utun)) carries the traffic",
					}, got.FakesV4)
				}
				assert.EqualError(t, got.FakesV6, fakesV6Off)
				var off6 *desync.FakesOffError
				require.ErrorAs(t, got.FakesV6, &off6)
				assert.Equal(t, desync.FakesOffIPv6Unsupported, off6.Kind)
				assert.Nil(t, got.V6)
				assert.Equal(t, ipv6StayedOn, got.IPv6Off)
			}
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
				"class":     "direct",
				"link":      "physical (IFT_ETHER)",
				"gateway":   "192.168.1.1",
				"src":       "192.168.1.11",
				"message":   "egress",
			},
		},
		{
			name:   "no gateway",
			egress: uplinkEgress,
			want: map[string]string{
				"family":    "ipv4",
				"interface": "ppp0",
				"class":     "uplink",
				"link":      "ppp (IFT_PPP)",
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
		wantErr   string
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
			name:      "vpn in tun",
			mode:      tunMode,
			ipv6:      true,
			egress6:   egress6(vpnEgress),
			wantOff:   ipv6OffVPN,
			wantLogs:  []string{egressInfo, vpnTUN6Warn},
			wantCalls: []string{callV4, callV6},
		},
		{
			name:      "vpn in proxy",
			mode:      proxyFakes,
			ipv6:      true,
			egress6:   egress6(vpnEgress),
			wantV6:    true,
			wantLogs:  []string{egressInfo, vpnProxy6Info},
			wantCalls: []string{callV4, callV6},
		},
		{
			name:      "unknown in tun",
			mode:      tunMode,
			ipv6:      true,
			egress6:   egress6(unknownEgress),
			wantV6:    true,
			wantLogs:  []string{egressInfo, egressInfo, unknownWarn},
			wantCalls: []string{callV4, callV6},
		},
		{
			name:      "unknown in proxy",
			mode:      proxyNoFakes,
			ipv6:      true,
			egress6:   egress6(unknownEgress),
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
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Equal(t, tc.wantErr, err.Error())
				return
			}
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
			assert.EqualError(t, got.FakesV6, fakesV6Off)
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

// pathVia returns the IPv4 path to dst through the interface of e.
func pathVia(dst netip.Addr, e *route.Egress) *route.Path {
	return &route.Path{Family: netutil.FamilyV4, Dst: dst, Iface: e.Route.Iface}
}

func TestDstFakeCheck(t *testing.T) {
	dst := netip.MustParseAddr("10.20.0.5")
	tcs := []struct {
		name         string
		path         *route.Path
		routeErr     error
		class        *route.Egress
		classErr     error
		wantErr      *desync.FakesOffError
		noStart      bool
		wantClassify bool
		wantLog      string
	}{
		{
			name: "same interface as at startup",
			path: pathVia(dst, directEgress),
		},
		{
			name:         "no startup egress",
			noStart:      true,
			path:         pathVia(dst, directEgress),
			class:        directEgress,
			wantClassify: true,
		},
		{
			name:         "split-tunnel VPN",
			path:         pathVia(dst, vpnEgress),
			class:        vpnEgress,
			wantClassify: true,
			wantErr: &desync.FakesOffError{
				Family:    netutil.FamilyV4,
				Kind:      desync.FakesOffDstViaVPN,
				Interface: "utun4",
				Reason:    "the route to 10.20.0.5 goes through a VPN (utun4)",
			},
		},
		{
			name:         "another uplink",
			path:         pathVia(dst, uplinkEgress),
			class:        uplinkEgress,
			wantClassify: true,
		},
		{
			name:         "unknown link",
			path:         pathVia(dst, unknownEgress),
			class:        unknownEgress,
			wantClassify: true,
		},
		{
			name:     "route lookup fails",
			routeErr: errors.New("no route"),
			wantLog:  "debug: route lookup failed; allowing fake packets",
		},
		{
			name:         "classification fails",
			path:         pathVia(dst, unknownEgress),
			classErr:     errors.New("loopback"),
			wantClassify: true,
			wantLog:      "debug: route classification failed; allowing fake packets",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			var routed []netip.Addr
			var classified bool
			start := directEgress
			if tc.noStart {
				start = nil
			}
			check := dstFakeCheck(
				zerolog.New(&buf).Level(zerolog.DebugLevel),
				start,
				func(a netip.Addr) (*route.Path, error) {
					routed = append(routed, a)
					return tc.path, tc.routeErr
				},
				func(p *route.Path) (*route.Egress, error) {
					classified = true
					assert.Same(t, tc.path, p)
					return tc.class, tc.classErr
				},
			)

			err := check(dst)

			if tc.wantErr == nil {
				assert.NoError(t, err)
			} else {
				assert.Equal(t, tc.wantErr, err)
			}
			assert.Equal(t, []netip.Addr{dst}, routed)
			assert.Equal(t, tc.wantClassify, classified)
			var wantLogs []string
			if tc.wantLog != "" {
				wantLogs = []string{tc.wantLog}
			}
			assert.Equal(t, wantLogs, logLines(t, &buf))
		})
	}
}
