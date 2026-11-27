//go:build freebsd

package tun

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/route"
)

func TestEgressControl_FreeBSD(t *testing.T) {
	rt := &route.Route{Iface: net.Interface{Index: 1, Name: "em0"}}
	assert.Nil(t, EgressControl(rt, 0), "no FIB, nothing to pin to")
	assert.Nil(t, EgressControl(rt, -1))
	assert.NotNil(t, EgressControl(rt, 2))
	assert.NotNil(t, EgressControl(nil, 2), "only the FIB matters")
}

func TestBindDialer_FreeBSD(t *testing.T) {
	egress4 := &route.Route{
		Family: netutil.FamilyV4,
		Iface:  net.Interface{Index: 999, Name: "em999"},
	}
	egress6 := &route.Route{
		Family: netutil.FamilyV6,
		Iface:  net.Interface{Index: 998, Name: "em998"},
	}

	t.Run("ipv6", func(t *testing.T) {
		n := &tunSystemNetworkFreeBSD{egress4: egress4, egress6: egress6, fibID: 2}
		var d net.Dialer
		require.NoError(t, n.BindDialer(&d, "tcp", net.ParseIP("2001:db8::1")))
		assert.Nil(t, d.LocalAddr, "the kernel picks the source address")
		assert.NotNil(t, d.Control)
	})

	t.Run("no ipv6 egress", func(t *testing.T) {
		n := &tunSystemNetworkFreeBSD{egress4: egress4, fibID: 2}
		var d net.Dialer
		err := n.BindDialer(&d, "tcp", net.ParseIP("2001:db8::1"))
		require.EqualError(t, err, "no ipv6 egress for target 2001:db8::1")
		assert.Nil(t, d.Control)
	})
}
