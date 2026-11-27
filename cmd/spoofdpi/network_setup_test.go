package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xvzc/spoofdpi/internal/config"
)

func TestIsNetworkSetupFatal(t *testing.T) {
	assert.True(t, isNetworkSetupFatal(config.AppModeTUN))
	assert.False(t, isNetworkSetupFatal(config.AppModeHTTP))
	assert.False(t, isNetworkSetupFatal(config.AppModeSOCKS5))
}
