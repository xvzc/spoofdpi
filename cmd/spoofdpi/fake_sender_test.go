package main

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/inject"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/packet"
)

func TestFakeSenderOptions(t *testing.T) {
	route := &netutil.Route{Iface: net.Interface{Index: 1, Name: "lo0"}}

	for _, mode := range []config.AppModeType{config.AppModeHTTP, config.AppModeSOCKS5} {
		t.Run(mode.String(), func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.App.Mode = mode
			assert.Nil(t, fakeSenderOptions(cfg, route).Control,
				"the proxy modes leave the route to the kernel")
		})
	}

	t.Run("tun", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.App.Mode = config.AppModeTUN
		cfg.App.FreebsdFIB = 2
		assert.NotNil(t, fakeSenderOptions(cfg, route).Control,
			"TUN mode pins the raw sockets like the dialed connections")
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
	route := &netutil.Route{Iface: net.Interface{Index: 4, Name: "en0"}}
	off := &packet.FakesOffError{Family: netutil.FamilyV4, Reason: "a VPN"}
	withMode := func(mode config.AppModeType) *config.Config {
		cfg := config.DefaultConfig()
		cfg.App.Mode = mode
		cfg.App.FreebsdFIB = 3
		return cfg
	}

	tcs := []struct {
		name    string
		goos    string
		cfg     *config.Config
		fakesV4 error
		want    string
	}{
		{"http", "darwin", withMode(config.AppModeHTTP), nil, "none"},
		{"socks5", "linux", withMode(config.AppModeSOCKS5), nil, "none"},
		{"tun on darwin", "darwin", withMode(config.AppModeTUN), nil, "en0"},
		{"tun on linux", "linux", withMode(config.AppModeTUN), nil, "en0"},
		{"tun on freebsd", "freebsd", withMode(config.AppModeTUN), nil, "fib 3"},
		{"fakes off", "darwin", withMode(config.AppModeTUN), off, "none"},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, fakesPinning(tc.goos, tc.cfg, route, tc.fakesV4))
		})
	}
}

func TestFakesState(t *testing.T) {
	assert.Equal(t, "on", fakesState(nil))
	assert.Equal(
		t,
		"off: IPv6 fakes are not supported yet",
		fakesState(&packet.FakesOffError{
			Family: netutil.FamilyV6,
			Reason: "IPv6 fakes are not supported yet",
		}),
	)
	assert.Equal(t, "off: boom", fakesState(errors.New("boom")))
}
