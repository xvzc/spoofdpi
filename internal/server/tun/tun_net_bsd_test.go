//go:build darwin || freebsd

package tun

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xvzc/spoofdpi/internal/route"
)

func TestGatewayIP(t *testing.T) {
	assert.Equal(t, "192.168.1.1", gatewayIP(&route.Route{
		Gateway: net.ParseIP("192.168.1.1"),
	}))
	assert.Equal(t, "", gatewayIP(&route.Route{}))
}
