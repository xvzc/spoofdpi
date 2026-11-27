package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/desync"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/packetio/inject"
	"github.com/xvzc/spoofdpi/internal/packetio/inject/injecttest"
	"github.com/xvzc/spoofdpi/internal/route"
)

func TestFakeSenderOptions(t *testing.T) {
	rt := &route.Route{Iface: net.Interface{Index: 1, Name: "lo0"}}

	for _, mode := range []config.AppModeType{config.AppModeHTTP, config.AppModeSOCKS5} {
		t.Run(mode.String(), func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.App.Mode = mode
			assert.Nil(t, fakeSenderOptions(cfg, rt).Control,
				"the proxy modes leave the route to the kernel")
		})
	}

	t.Run("tun", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.App.Mode = config.AppModeTUN
		cfg.App.FreebsdFIB = 2
		assert.NotNil(t, fakeSenderOptions(cfg, rt).Control,
			"TUN mode pins the raw sockets like the dialed connections")
		rt6 := &route.Route{
			Family: netutil.FamilyV6,
			Iface:  net.Interface{Index: 1, Name: "lo0"},
		}
		assert.NotNil(t, fakeSenderOptions(cfg, rt6).Control,
			"TUN mode returns a control for an IPv6 route as well")
	})
}

func TestFakeSenderError(t *testing.T) {
	needsRoot := fmt.Errorf("%w: listen ip4:255: %w", inject.ErrNeedsRoot, syscall.EPERM)
	err := fakeSenderError(needsRoot)
	assert.ErrorIs(t, err, inject.ErrNeedsRoot)
	assert.Contains(t, err.Error(), "fake packet sender: ")
	assert.Contains(t, err.Error(), "run as root, or set tls.fake-preflight, "+
		"tls.fake-stutter and udp.fake-preflight to 0, globally and in every "+
		"[[rules]] entry that sets them")

	other := errors.New("on eth0: network is unreachable")
	err = fakeSenderError(other)
	assert.ErrorIs(t, err, other)
	assert.Equal(
		t,
		"fake packet sender: on eth0: network is unreachable",
		err.Error(),
	)
}

func TestFakesPinning(t *testing.T) {
	rt := &route.Route{Iface: net.Interface{Index: 4, Name: "en0"}}
	withMode := func(mode config.AppModeType) *config.Config {
		cfg := config.DefaultConfig()
		cfg.App.Mode = mode
		cfg.App.FreebsdFIB = 3
		return cfg
	}

	tcs := []struct {
		name string
		goos string
		cfg  *config.Config
		want string
	}{
		{"http", "darwin", withMode(config.AppModeHTTP), "none"},
		{"socks5", "linux", withMode(config.AppModeSOCKS5), "none"},
		{"tun on darwin", "darwin", withMode(config.AppModeTUN), "en0"},
		{"tun on linux", "linux", withMode(config.AppModeTUN), "en0"},
		{"tun on freebsd", "freebsd", withMode(config.AppModeTUN), "fib 3"},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, fakesPinning(tc.goos, tc.cfg, rt))
		})
	}
}

func TestFakesState(t *testing.T) {
	assert.Equal(t, "on", fakesState(nil))
	assert.Equal(
		t,
		"off: IPv6 fakes are not supported in TUN mode yet",
		fakesState(&desync.FakesOffError{
			Family: netutil.FamilyV6,
			Kind:   desync.FakesOffIPv6Unsupported,
			Reason: "IPv6 fakes are not supported in TUN mode yet",
		}),
	)
	assert.Equal(t, "off: boom", fakesState(errors.New("boom")))
}

func TestFakesOffV6(t *testing.T) {
	egress6 := &route.Egress{Route: route.Route{
		Family: netutil.FamilyV6,
		Iface:  net.Interface{Index: 1, Name: "en0"},
	}}
	withMode := func(mode config.AppModeType) *config.Config {
		cfg := config.DefaultConfig()
		cfg.App.Mode = mode
		return cfg
	}
	senderErr := errors.New("listen ip6:tcp: protocol not available")

	tcs := []struct {
		name       string
		cfg        *config.Config
		startup    startupNet
		senderErr  error
		wantKind   string
		wantReason string
	}{
		{
			name:    "http with an ipv6 egress and sender",
			cfg:     withMode(config.AppModeHTTP),
			startup: startupNet{V6: egress6},
		},
		{
			name:    "socks5 with an ipv6 egress and sender",
			cfg:     withMode(config.AppModeSOCKS5),
			startup: startupNet{V6: egress6},
		},
		{
			name:       "tun",
			cfg:        withMode(config.AppModeTUN),
			startup:    startupNet{V6: egress6},
			wantKind:   desync.FakesOffIPv6Unsupported,
			wantReason: "IPv6 fakes are not supported in TUN mode yet",
		},
		{
			name:       "ipv6 sender failed",
			cfg:        withMode(config.AppModeHTTP),
			startup:    startupNet{V6: egress6},
			senderErr:  senderErr,
			wantKind:   desync.FakesOffIPv6NoSender,
			wantReason: "the IPv6 sender did not open: " + senderErr.Error(),
		},
		{
			name:       "ipv6 not enabled",
			cfg:        withMode(config.AppModeHTTP),
			wantKind:   desync.FakesOffIPv6Disabled,
			wantReason: "IPv6 is not enabled",
		},
		{
			name:       "ipv6 turned off for want of a route",
			cfg:        withMode(config.AppModeSOCKS5),
			startup:    startupNet{IPv6Off: ipv6OffNoRoute},
			wantKind:   desync.FakesOffIPv6Disabled,
			wantReason: "no usable IPv6 route was found",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			err := fakesOffV6(tc.cfg, tc.startup, tc.senderErr)

			if tc.wantKind == "" {
				assert.NoError(t, err)
				return
			}
			var off *desync.FakesOffError
			require.ErrorAs(t, err, &off)
			assert.Equal(t, netutil.FamilyV6, off.Family)
			assert.Equal(t, tc.wantKind, off.Kind)
			assert.Equal(t, tc.wantReason, off.Reason)
			assert.Equal(t, "off: "+tc.wantReason, fakesState(err),
				"the startup line says why")
		})
	}
}

func TestEgressIfaces(t *testing.T) {
	en0 := net.Interface{Index: 4, Name: "en0"}
	gif0 := net.Interface{Index: 7, Name: "gif0"}
	egressOn := func(iface net.Interface) *route.Egress {
		return &route.Egress{Route: route.Route{Iface: iface}}
	}
	v4 := netutil.NewFamilySet(netutil.FamilyV4)
	v6 := netutil.NewFamilySet(netutil.FamilyV6)

	withV6 := desync.Senders{V4: &injecttest.Sender{}, V6: &injecttest.Sender{}}
	v4Only := desync.Senders{V4: &injecttest.Sender{}}

	tcs := []struct {
		name    string
		startup startupNet
		senders desync.Senders
		want    []desync.EgressIface
	}{
		{
			"ipv4 only",
			startupNet{V4: egressOn(en0)},
			v4Only,
			[]desync.EgressIface{{Iface: en0, Fams: v4}},
		},
		{
			"both families on one interface",
			startupNet{V4: egressOn(en0), V6: egressOn(en0)},
			withV6,
			[]desync.EgressIface{{
				Iface: en0,
				Fams:  netutil.NewFamilySet(netutil.FamilyV4, netutil.FamilyV6),
			}},
		},
		{
			"ipv6 on another interface",
			startupNet{V4: egressOn(en0), V6: egressOn(gif0)},
			withV6,
			[]desync.EgressIface{{Iface: en0, Fams: v4}, {Iface: gif0, Fams: v6}},
		},
		{
			"ipv6 without its sender",
			startupNet{V4: egressOn(en0), V6: egressOn(gif0)},
			v4Only,
			[]desync.EgressIface{{Iface: en0, Fams: v4}},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, egressIfaces(tc.startup, tc.senders))
		})
	}
}

// senderOpener records the families it opens senders for, and fails for
// those in fail.
type senderOpener struct {
	fail   map[netutil.Family]error
	opened []netutil.Family
}

func (o *senderOpener) open(
	fam netutil.Family,
	_ inject.Options,
) (inject.Sender, error) {
	if err := o.fail[fam]; err != nil {
		return nil, err
	}
	o.opened = append(o.opened, fam)
	return &injecttest.Sender{}, nil
}

func TestOpenFakeSenders(t *testing.T) {
	egress := &route.Egress{
		Route: route.Route{Iface: net.Interface{Index: 1, Name: "en0"}},
	}
	egress6 := &route.Egress{Route: route.Route{
		Family: netutil.FamilyV6,
		Iface:  net.Interface{Index: 1, Name: "en0"},
	}}
	withMode := func(mode config.AppModeType) *config.Config {
		cfg := config.DefaultConfig()
		cfg.App.Mode = mode
		return cfg
	}
	failed := errors.New("protocol not available")

	tcs := []struct {
		name     string
		cfg      *config.Config
		startup  startupNet
		fail     map[netutil.Family]error
		wantOpen []netutil.Family
		wantV6   bool
		// wantOffKind is the kind of the reason fakes are off for IPv6,
		// or "" when they are on.
		wantOffKind string
		wantWarn    bool
	}{
		{
			name:        "ipv4 only",
			cfg:         withMode(config.AppModeHTTP),
			startup:     startupNet{V4: egress},
			wantOpen:    []netutil.Family{netutil.FamilyV4},
			wantOffKind: desync.FakesOffIPv6Disabled,
		},
		{
			name:     "ipv6 egress in a proxy mode",
			cfg:      withMode(config.AppModeSOCKS5),
			startup:  startupNet{V4: egress, V6: egress6},
			wantOpen: []netutil.Family{netutil.FamilyV4, netutil.FamilyV6},
			wantV6:   true,
		},
		{
			name:        "ipv6 egress in TUN mode",
			cfg:         withMode(config.AppModeTUN),
			startup:     startupNet{V4: egress, V6: egress6},
			wantOpen:    []netutil.Family{netutil.FamilyV4},
			wantOffKind: desync.FakesOffIPv6Unsupported,
		},
		{
			name:        "ipv6 sender failure is not fatal",
			cfg:         withMode(config.AppModeHTTP),
			startup:     startupNet{V4: egress, V6: egress6},
			fail:        map[netutil.Family]error{netutil.FamilyV6: failed},
			wantOpen:    []netutil.Family{netutil.FamilyV4},
			wantOffKind: desync.FakesOffIPv6NoSender,
			wantWarn:    true,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			opener := &senderOpener{fail: tc.fail}

			senders, fakesV6, err := openFakeSenders(
				zerolog.New(&logs),
				tc.cfg,
				tc.startup,
				opener.open,
			)

			require.NoError(t, err)
			assert.Equal(t, tc.wantOpen, opener.opened)
			assert.NotNil(t, senders.V4)
			assert.Equal(t, tc.wantV6, senders.V6 != nil)
			if tc.wantOffKind == "" {
				assert.NoError(t, fakesV6)
			} else {
				var off *desync.FakesOffError
				require.ErrorAs(t, fakesV6, &off)
				assert.Equal(t, tc.wantOffKind, off.Kind)
			}
			if tc.wantWarn {
				assert.Contains(t, logs.String(), `"level":"warn"`)
				assert.Contains(t, logs.String(), "protocol not available")
				assert.Contains(t, logs.String(),
					"failed to open the IPv6 fake packet sender; "+
						"fake packets are off for IPv6")
			} else {
				assert.Empty(t, logs.String())
			}
		})
	}

	t.Run("ipv4 sender failure is fatal", func(t *testing.T) {
		opener := &senderOpener{fail: map[netutil.Family]error{netutil.FamilyV4: failed}}

		_, _, err := openFakeSenders(
			zerolog.Nop(),
			withMode(config.AppModeHTTP),
			startupNet{V4: egress, V6: egress6},
			opener.open,
		)

		require.ErrorIs(t, err, failed)
		assert.Equal(t, "fake packet sender: protocol not available", err.Error())
		assert.Empty(t, opener.opened, "no ipv6 sender is opened")
	})
}

// fakeStackOpeners returns openers whose senders are recorded in senders,
// and whose stacks are opened with the interfaces recorded in ifaces, or
// fail with tcpErr or udpErr.
func fakeStackOpeners(
	senders *[]*injecttest.Sender,
	ifaces *[]desync.EgressIface,
	tcpErr, udpErr error,
) stackOpeners {
	return stackOpeners{
		sender: func(netutil.Family, inject.Options) (inject.Sender, error) {
			s := &injecttest.Sender{}
			*senders = append(*senders, s)
			return s, nil
		},
		tcp: func(
			_ string,
			_ zerolog.Logger,
			got []desync.EgressIface,
			_ desync.Senders,
			_ *desync.HopStore,
		) (*desync.TCPStack, error) {
			*ifaces = got
			if tcpErr != nil {
				return nil, tcpErr
			}
			return &desync.TCPStack{}, nil
		},
		udp: func(
			_ string,
			_ zerolog.Logger,
			got []desync.EgressIface,
			_ desync.Senders,
			_ *desync.HopStore,
		) (*desync.UDPStack, error) {
			*ifaces = got
			if udpErr != nil {
				return nil, udpErr
			}
			return &desync.UDPStack{}, nil
		},
	}
}

func TestSetupNetworkStack(t *testing.T) {
	en0 := net.Interface{Index: 4, Name: "en0"}
	startup := startupNet{
		V4: &route.Egress{Route: route.Route{Iface: en0}},
		V6: &route.Egress{Route: route.Route{Family: netutil.FamilyV6, Iface: en0}},
	}
	withStacks := func() *config.Config {
		cfg := config.DefaultConfig()
		cfg.HTTPS.FakePreflight = 1
		cfg.UDP.FakePreflight = 1
		return cfg
	}
	failed := errors.New("on en0: set SYN/ACK capture filter: program rejected")

	t.Run("logs the families of each interface", func(t *testing.T) {
		var senders []*injecttest.Sender
		var ifaces []desync.EgressIface
		var logs bytes.Buffer

		tcp, udp, hops, fakesV6, err := setupNetworkStack(
			context.Background(),
			zerolog.New(&logs),
			startup,
			withStacks(),
			fakeStackOpeners(&senders, &ifaces, nil, nil),
		)

		require.NoError(t, err)
		assert.NotNil(t, tcp)
		assert.NotNil(t, udp)
		assert.NotNil(t, hops)
		assert.NoError(t, fakesV6, "fakes are on for IPv6 in a proxy mode")
		require.Len(t, senders, 2, "both senders open in a proxy mode")
		assert.Equal(t, []desync.EgressIface{{
			Iface: en0,
			Fams:  netutil.NewFamilySet(netutil.FamilyV4, netutil.FamilyV6),
		}}, ifaces)
		assert.Contains(t, logs.String(),
			`"name":"en0","families":["ipv4","ipv6"],"message":" interface"`)
	})

	t.Run("tun mode keeps ipv6 fakes off", func(t *testing.T) {
		var senders []*injecttest.Sender
		var ifaces []desync.EgressIface
		cfg := withStacks()
		cfg.App.Mode = config.AppModeTUN

		_, _, _, fakesV6, err := setupNetworkStack(
			context.Background(),
			zerolog.Nop(),
			startup,
			cfg,
			fakeStackOpeners(&senders, &ifaces, nil, nil),
		)

		require.NoError(t, err)
		var off *desync.FakesOffError
		require.ErrorAs(t, fakesV6, &off)
		assert.Equal(t, desync.FakesOffIPv6Unsupported, off.Kind)
		assert.Len(t, senders, 1, "no IPv6 sender opens in TUN mode")
		assert.Equal(t, []desync.EgressIface{{
			Iface: en0,
			Fams:  netutil.NewFamilySet(netutil.FamilyV4),
		}}, ifaces)
	})

	for _, tc := range []struct {
		name           string
		tcpErr, udpErr error
		want           string
	}{
		{"tcp", failed, nil, "tcp pcap handle " + failed.Error()},
		{"udp", nil, failed, "udp pcap handle " + failed.Error()},
	} {
		t.Run(tc.name+" stack error closes the senders", func(t *testing.T) {
			var senders []*injecttest.Sender
			var ifaces []desync.EgressIface

			tcp, udp, _, _, err := setupNetworkStack(
				context.Background(),
				zerolog.Nop(),
				startup,
				withStacks(),
				fakeStackOpeners(&senders, &ifaces, tc.tcpErr, tc.udpErr),
			)

			require.ErrorIs(t, err, failed)
			assert.EqualError(t, err, tc.want)
			assert.Nil(t, udp)
			if tc.tcpErr != nil {
				assert.Nil(t, tcp)
			}
			require.Len(t, senders, 2)
			for _, s := range senders {
				assert.True(t, s.Closed(), "every sender is closed")
			}
		})
	}
}
