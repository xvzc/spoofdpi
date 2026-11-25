//go:build linux

package tun

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xvzc/spoofdpi/internal/route"
)

func TestEgressControl_Linux(t *testing.T) {
	assert.Nil(t, EgressControl(nil, 0))
	assert.Nil(t, EgressControl(&route.Route{}, 0))
	rt := &route.Route{Iface: net.Interface{Index: 2, Name: "eth0"}}
	assert.NotNil(t, EgressControl(rt, 0))
}
