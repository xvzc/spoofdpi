package main

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/desync"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/packetio/inject"
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
		"off: IPv6 fakes are not supported yet",
		fakesState(&desync.FakesOffError{
			Family: netutil.FamilyV6,
			Reason: "IPv6 fakes are not supported yet",
		}),
	)
	assert.Equal(t, "off: boom", fakesState(errors.New("boom")))
}
