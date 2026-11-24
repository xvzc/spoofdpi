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
)

// fakeRouteFinder answers the calls of a routeFinder with fixed results per
// family and records them.
type fakeRouteFinder struct {
	egress4    *netutil.Egress
	err4       error
	egress6    *netutil.Egress
	err6       error
	ipv6Egress bool
	calls      []string // family gateway%zone
}

func (f *fakeRouteFinder) finder() routeFinder {
	return routeFinder{
		egress: func(fam netutil.Family, gateway net.IP, zone string) (*netutil.Egress, error) {
			f.calls = append(f.calls, fmt.Sprintf("%s %v%%%s", fam, gateway, zone))
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

// Egresses of each class, as netutil.ClassifyEgress explains them.
var (
	directEgress = &netutil.Egress{
		Route: netutil.Route{
			Family:  netutil.FamilyV4,
			Iface:   net.Interface{Index: 4, Name: "en0"},
			LocalIP: net.IPv4(192, 168, 1, 11).To4(),
			Gateway: net.IPv4(192, 168, 1, 1).To4(),
		},
		Link: netutil.LinkInfo{
			Index:  4,
			Name:   "en0",
			Kind:   netutil.LinkPhysical,
			Detail: "IFT_ETHER",
		},
		Class:  netutil.EgressDirect,
		Reason: "physical link en0 (IFT_ETHER)",
	}
	uplinkEgress = &netutil.Egress{
		Route: netutil.Route{
			Family:  netutil.FamilyV4,
			Iface:   net.Interface{Index: 9, Name: "ppp0"},
			LocalIP: net.IPv4(100, 64, 0, 2).To4(),
		},
		Link: netutil.LinkInfo{
			Index:  9,
			Name:   "ppp0",
			Kind:   netutil.LinkPPP,
			Detail: "IFT_PPP",
		},
		Class:  netutil.EgressUplink,
		Reason: "ppp link ppp0 (IFT_PPP) is the only default route",
	}
	vpnEgress = &netutil.Egress{
		Route: netutil.Route{
			Family:  netutil.FamilyV4,
			Iface:   net.Interface{Index: 12, Name: "utun4"},
			LocalIP: net.IPv4(10, 8, 0, 2).To4(),
		},
		Link: netutil.LinkInfo{
			Index:  12,
			Name:   "utun4",
			Kind:   netutil.LinkVPN,
			Detail: "utun",
		},
		Class:  netutil.EgressVPN,
		Reason: "VPN link utun4 (utun)",
	}
	unknownEgress = &netutil.Egress{
		Route: netutil.Route{
			Family:  netutil.FamilyV4,
			Iface:   net.Interface{Index: 13, Name: "tun0"},
			LocalIP: net.IPv4(10, 9, 0, 2).To4(),
		},
		Link: netutil.LinkInfo{
			Index: 13, Name: "tun0", Kind: netutil.LinkUnknown, Detail: "IFT_OTHER p2p",
		},
		Class:  netutil.EgressUnknown,
		Reason: "cannot tell whether tun0 (IFT_OTHER p2p) is a VPN",
	}
)

// egress6 returns a copy of e as an IPv6 egress.
func egress6(e *netutil.Egress) *netutil.Egress {
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
	ignoredWarn   = "warn: gateway is ignored; only fake packets and tun mode use it"
	unknownWarn   = "warn: cannot tell whether tun0 (IFT_OTHER p2p) is a VPN; proceeding as if it were not; if it is a full-tunnel VPN, fake packets and TUN mode do not work through it"
	vpnFakesWarn  = "warn: a full-tunnel VPN (VPN link utun4 (utun)) carries the traffic; fake packets are disabled"
	vpnFakesOff   = "fake packets are off for ipv4: a full-tunnel VPN (VPN link utun4 (utun)) carries the traffic"
	vpnTUNErr     = "TUN mode cannot run while a full-tunnel VPN carries the traffic (VPN link utun4 (utun)); disconnect the VPN or use the HTTP or SOCKS5 mode"
	gatewayNote   = "; the gateway option does not override this"
	fakesV6Off    = "fake packets are off for ipv6: IPv6 fakes are not supported yet"
	ignored6Warn  = "warn: IPv6 gateway fe80::1%en0 is ignored; it is used only when ipv6 is enabled"
	fallback6Warn = "warn: IPv6 is enabled but no usable IPv6 route was found; running with IPv6 disabled"
	vpnTUN6Warn   = "warn: a full-tunnel VPN (VPN link utun4 (utun)) carries IPv6; running with IPv6 disabled"
	vpnProxy6Info = "info: IPv6 goes through a full-tunnel VPN (VPN link utun4 (utun))"
	gatewayV4     = "10.0.0.1"
	gatewayV6     = "fe80::1"
	gatewayV6Zone = "en0"
	callV4NoGW    = "ipv4 <nil>%"
	callV4GW      = "ipv4 10.0.0.1%"
	callV6NoGW    = "ipv6 <nil>%"
	callV6GW      = "ipv6 fe80::1%en0"
)

type startupMode string

const (
	proxyNoFakes startupMode = "proxy without fakes"
	proxyFakes   startupMode = "proxy with fakes"
	tunMode      startupMode = "tun"
)

// startupConfig returns the default config in mode, with the gateways
// that are set.
func startupConfig(mode startupMode, gw4 bool, ipv6 bool, gw6 bool) *config.Config {
	cfg := config.DefaultConfig()
	switch mode {
	case proxyFakes:
		cfg.HTTPS.FakePreflight = 1
	case tunMode:
		cfg.App.Mode = config.AppModeTUN
	}
	if gw4 {
		cfg.App.Gateway.V4 = net.ParseIP(gatewayV4).To4()
	}
	if gw6 {
		cfg.App.Gateway.V6 = net.ParseIP(gatewayV6)
		cfg.App.Gateway.V6Zone = gatewayV6Zone
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
		egress      *netutil.Egress
		mode        startupMode
		gateway     bool
		wantErr     string
		wantV4      bool
		wantFakesV4 string
		wantLogs    []string
		wantCalls   []string
	}
	var tcs []tc

	// Without fake packets or TUN mode, no IPv4 egress is discovered.
	for _, e := range []*netutil.Egress{directEgress, uplinkEgress, vpnEgress, unknownEgress} {
		tcs = append(tcs,
			tc{
				name:   e.Class.String() + "/" + string(proxyNoFakes) + "/no gateway",
				egress: e,
				mode:   proxyNoFakes,
			},
			tc{
				name:     e.Class.String() + "/" + string(proxyNoFakes) + "/gateway",
				egress:   e,
				mode:     proxyNoFakes,
				gateway:  true,
				wantLogs: []string{ignoredWarn},
			},
		)
	}

	tcs = append(tcs,
		// direct
		tc{
			name:      "direct/proxy with fakes/no gateway",
			egress:    directEgress,
			mode:      proxyFakes,
			wantV4:    true,
			wantLogs:  []string{egressInfo},
			wantCalls: []string{callV4NoGW},
		},
		tc{
			name:      "direct/proxy with fakes/gateway",
			egress:    directEgress,
			mode:      proxyFakes,
			gateway:   true,
			wantV4:    true,
			wantLogs:  []string{egressInfo},
			wantCalls: []string{callV4GW},
		},
		tc{
			name: "direct/tun/no gateway", egress: directEgress, mode: tunMode,
			wantV4: true, wantLogs: []string{egressInfo}, wantCalls: []string{callV4NoGW},
		},
		tc{
			name: "direct/tun/gateway", egress: directEgress, mode: tunMode, gateway: true,
			wantV4: true, wantLogs: []string{egressInfo}, wantCalls: []string{callV4GW},
		},
		// uplink: a point-to-point default route without a gateway works
		tc{
			name:      "uplink/proxy with fakes/no gateway",
			egress:    uplinkEgress,
			mode:      proxyFakes,
			wantV4:    true,
			wantLogs:  []string{egressInfo},
			wantCalls: []string{callV4NoGW},
		},
		tc{
			name:      "uplink/proxy with fakes/gateway",
			egress:    uplinkEgress,
			mode:      proxyFakes,
			gateway:   true,
			wantV4:    true,
			wantLogs:  []string{egressInfo},
			wantCalls: []string{callV4GW},
		},
		tc{
			name: "uplink/tun/no gateway", egress: uplinkEgress, mode: tunMode,
			wantV4: true, wantLogs: []string{egressInfo}, wantCalls: []string{callV4NoGW},
		},
		tc{
			name: "uplink/tun/gateway", egress: uplinkEgress, mode: tunMode, gateway: true,
			wantV4: true, wantLogs: []string{egressInfo}, wantCalls: []string{callV4GW},
		},
		// vpn
		tc{
			name: "vpn/proxy with fakes/no gateway", egress: vpnEgress, mode: proxyFakes,
			wantV4: true, wantFakesV4: vpnFakesOff,
			wantLogs:  []string{egressInfo, vpnFakesWarn},
			wantCalls: []string{callV4NoGW},
		},
		tc{
			name:        "vpn/proxy with fakes/gateway",
			egress:      vpnEgress,
			mode:        proxyFakes,
			gateway:     true,
			wantV4:      true,
			wantFakesV4: vpnFakesOff,
			wantLogs: []string{
				egressInfo,
				vpnFakesWarn + " (gateway 10.0.0.1 is ignored)",
			},
			wantCalls: []string{callV4GW},
		},
		tc{
			name: "vpn/tun/no gateway", egress: vpnEgress, mode: tunMode,
			wantErr:   vpnTUNErr,
			wantLogs:  []string{egressInfo},
			wantCalls: []string{callV4NoGW},
		},
		tc{
			name: "vpn/tun/gateway", egress: vpnEgress, mode: tunMode, gateway: true,
			wantErr:   vpnTUNErr + gatewayNote,
			wantLogs:  []string{egressInfo},
			wantCalls: []string{callV4GW},
		},
		// unknown: warn and proceed
		tc{
			name:      "unknown/proxy with fakes/no gateway",
			egress:    unknownEgress,
			mode:      proxyFakes,
			wantV4:    true,
			wantLogs:  []string{egressInfo, unknownWarn},
			wantCalls: []string{callV4NoGW},
		},
		tc{
			name:      "unknown/proxy with fakes/gateway",
			egress:    unknownEgress,
			mode:      proxyFakes,
			gateway:   true,
			wantV4:    true,
			wantLogs:  []string{egressInfo, unknownWarn},
			wantCalls: []string{callV4GW},
		},
		tc{
			name:      "unknown/tun/no gateway",
			egress:    unknownEgress,
			mode:      tunMode,
			wantV4:    true,
			wantLogs:  []string{egressInfo, unknownWarn},
			wantCalls: []string{callV4NoGW},
		},
		tc{
			name:      "unknown/tun/gateway",
			egress:    unknownEgress,
			mode:      tunMode,
			gateway:   true,
			wantV4:    true,
			wantLogs:  []string{egressInfo, unknownWarn},
			wantCalls: []string{callV4GW},
		},
	)

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			finder := fakeRouteFinder{egress4: tc.egress}
			cfg := startupConfig(tc.mode, tc.gateway, false, false)

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
				}
				assert.EqualError(t, got.FakesV6, fakesV6Off)
				assert.Nil(t, got.V6)
				assert.False(t, got.IPv6Disabled)
			}
			assert.Equal(t, tc.wantLogs, logLines(t, &buf))
			assert.Equal(t, tc.wantCalls, finder.calls)
		})
	}
}

func TestDiscoverEgresses_IPv4Errors(t *testing.T) {
	noRoute := fmt.Errorf(
		"discover egress: route lookup 192.0.2.1: %w",
		netutil.ErrNoIPv4Route,
	)
	tcs := []struct {
		name       string
		gateway    bool
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
				"fake packets, use HTTP/SOCKS5 mode, or set --gateway: discover egress: " +
				"route lookup 192.0.2.1: no IPv4 default route",
			wantNoV4: true,
		},
		{
			name: "discovery fails",
			err:  errors.New("discover egress: route lookup 192.0.2.1: permission denied"),
			wantErr: "failed to find default route: discover egress: route lookup 192.0.2.1: " +
				"permission denied; set --gateway, or disable fake packets and use HTTP/SOCKS5 mode",
		},
		{
			name:    "explicit gateway fails",
			gateway: true,
			err:     errors.New("no interface is on the same subnet as gateway 10.0.0.1"),
			wantErr: "failed to find default route: no interface is on the same subnet as " +
				"gateway 10.0.0.1; check --gateway, or remove it to use the system's default route",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			finder := fakeRouteFinder{err4: tc.err, ipv6Egress: tc.ipv6Egress}
			cfg := startupConfig(tunMode, tc.gateway, false, false)

			_, err := discoverEgresses(zerolog.Nop(), cfg, finder.finder())

			require.Error(t, err)
			assert.Equal(t, tc.wantErr, err.Error())
			assert.Equal(t, tc.wantNoV4, errors.Is(err, netutil.ErrNoIPv4Route))
		})
	}
}

// TestDiscoverEgresses_EgressLine checks the fields of the egress line,
// for a route with a gateway and one without.
func TestDiscoverEgresses_EgressLine(t *testing.T) {
	tcs := []struct {
		name   string
		egress *netutil.Egress
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
				startupConfig(tunMode, false, false, false),
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
		netutil.ErrNoIPv6Route,
	)
	eafnosupport := fmt.Errorf(
		"discover egress: route lookup 2001:db8::1: %w",
		syscall.EAFNOSUPPORT,
	)
	tcs := []struct {
		name         string
		mode         startupMode
		ipv6         bool
		gw6          bool
		egress6      *netutil.Egress
		err6         error
		wantErr      string
		wantV6       bool
		wantDisabled bool
		wantLogs     []string
		wantCalls    []string
	}{
		{
			name:     "ipv6 off with an ipv6 gateway",
			mode:     proxyNoFakes,
			gw6:      true,
			wantLogs: []string{ignored6Warn},
		},
		{
			name:      "direct",
			mode:      proxyNoFakes,
			ipv6:      true,
			egress6:   egress6(directEgress),
			wantV6:    true,
			wantLogs:  []string{egressInfo},
			wantCalls: []string{callV6NoGW},
		},
		{
			name:      "explicit ipv6 gateway",
			mode:      proxyNoFakes,
			ipv6:      true,
			gw6:       true,
			egress6:   egress6(directEgress),
			wantV6:    true,
			wantLogs:  []string{egressInfo},
			wantCalls: []string{callV6GW},
		},
		{
			name:         "no route",
			mode:         proxyNoFakes,
			ipv6:         true,
			err6:         noRoute6,
			wantDisabled: true,
			wantLogs:     []string{fallback6Warn},
			wantCalls:    []string{callV6NoGW},
		},
		{
			name:         "address family not supported",
			mode:         proxyFakes,
			ipv6:         true,
			err6:         eafnosupport,
			wantDisabled: true,
			wantLogs:     []string{egressInfo, fallback6Warn},
			wantCalls:    []string{callV4NoGW, callV6NoGW},
		},
		{
			name:         "vpn in tun",
			mode:         tunMode,
			ipv6:         true,
			egress6:      egress6(vpnEgress),
			wantDisabled: true,
			wantLogs:     []string{egressInfo, vpnTUN6Warn},
			wantCalls:    []string{callV4NoGW, callV6NoGW},
		},
		{
			name:      "vpn in proxy",
			mode:      proxyFakes,
			ipv6:      true,
			egress6:   egress6(vpnEgress),
			wantV6:    true,
			wantLogs:  []string{egressInfo, vpnProxy6Info},
			wantCalls: []string{callV4NoGW, callV6NoGW},
		},
		{
			name:      "unknown in tun",
			mode:      tunMode,
			ipv6:      true,
			egress6:   egress6(unknownEgress),
			wantV6:    true,
			wantLogs:  []string{egressInfo, egressInfo, unknownWarn},
			wantCalls: []string{callV4NoGW, callV6NoGW},
		},
		{
			name:      "unknown in proxy",
			mode:      proxyNoFakes,
			ipv6:      true,
			egress6:   egress6(unknownEgress),
			wantV6:    true,
			wantLogs:  []string{egressInfo},
			wantCalls: []string{callV6NoGW},
		},
		{
			name: "explicit ipv6 gateway fails",
			mode: proxyNoFakes,
			ipv6: true,
			gw6:  true,
			err6: errors.New(`gateway fe80::1: zone "en0": no such network interface`),
			wantErr: `failed to use IPv6 gateway: gateway fe80::1: zone "en0": no such ` +
				`network interface; check the IPv6 address of --gateway, or remove it ` +
				`to use the system's IPv6 default route`,
			wantCalls: []string{callV6GW},
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
			cfg := startupConfig(tc.mode, false, tc.ipv6, tc.gw6)

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
			assert.Equal(t, tc.wantDisabled, got.IPv6Disabled)
			assert.Equal(t, tc.ipv6 && !tc.wantDisabled, cfg.IPv6Enabled(), "IPv6Enabled")
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
	finder := fakeRouteFinder{err6: netutil.ErrNoIPv6Route}

	got, err := discoverEgresses(zerolog.Nop(), cfg, finder.finder())

	require.NoError(t, err)
	assert.True(t, got.IPv6Disabled)
	assert.Equal(t, []string{callV6NoGW}, finder.calls)
	assert.False(t, cfg.IPv6Enabled())
	for _, r := range cfg.Rules {
		assert.False(t, r.Config.IPv6, r.Name)
		assert.Equal(t, config.DNSQueryIPv4, r.Config.DNS.QType, r.Name)
	}
	assert.True(t, cfg.Rules[1].IPv4Only(), "a rule with ipv6 = false keeps to IPv4")
}
