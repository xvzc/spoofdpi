//go:build freebsd

package tun

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xvzc/spoofdpi/internal/route"
)

func TestEgressControl_FreeBSD(t *testing.T) {
	rt := &route.Route{Iface: net.Interface{Index: 1, Name: "em0"}}
	assert.Nil(t, EgressControl(rt, 0), "no FIB, nothing to pin to")
	assert.Nil(t, EgressControl(rt, -1))
	assert.NotNil(t, EgressControl(rt, 2))
	assert.NotNil(t, EgressControl(nil, 2), "only the FIB matters")
}
