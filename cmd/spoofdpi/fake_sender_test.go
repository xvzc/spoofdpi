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

	other := errors.New("on eth0: resolve gateway MAC: timed out")
	err = fakeSenderError(other)
	assert.ErrorIs(t, err, other)
	assert.Equal(
		t,
		"fake packet sender: on eth0: resolve gateway MAC: timed out",
		err.Error(),
	)
}
