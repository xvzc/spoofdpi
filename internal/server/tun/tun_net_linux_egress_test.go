//go:build linux

package tun

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xvzc/spoofdpi/internal/netutil"
)

func TestEgressControl_Linux(t *testing.T) {
	assert.Nil(t, EgressControl(nil, 0))
	assert.Nil(t, EgressControl(&netutil.Route{}, 0))
	route := &netutil.Route{Iface: net.Interface{Index: 2, Name: "eth0"}}
	assert.NotNil(t, EgressControl(route, 0))
}
