//go:build darwin || linux || freebsd

package tun

import (
	"net"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/route"
)

func TestEgressFor(t *testing.T) {
	egress4 := &route.Route{
		Family: netutil.FamilyV4,
		Iface:  net.Interface{Index: 2, Name: "eth0"},
	}
	egress6 := &route.Route{
		Family: netutil.FamilyV6,
		Iface:  net.Interface{Index: 3, Name: "eth1"},
	}

	tcs := []struct {
		name    string
		egress4 *route.Route
		egress6 *route.Route
		target  net.IP
		want    *route.Route
		wantErr string
	}{
		{"ipv4", egress4, egress6, net.ParseIP("192.0.2.1"), egress4, ""},
		{"ipv4-mapped", egress4, egress6, net.ParseIP("::ffff:192.0.2.1"), egress4, ""},
		{"ipv6", egress4, egress6, net.ParseIP("2001:db8::1"), egress6, ""},
		{
			"no ipv6 egress", egress4, nil, net.ParseIP("2001:db8::1"), nil,
			"no ipv6 egress for target 2001:db8::1",
		},
		{
			"no ipv4 egress", nil, egress6, net.ParseIP("192.0.2.1"), nil,
			"no ipv4 egress for target 192.0.2.1",
		},
		{
			"egress without interface",
			&route.Route{},
			egress6,
			net.ParseIP("192.0.2.1"),
			nil,
			"no ipv4 egress for target 192.0.2.1",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got, err := egressFor(tc.egress4, tc.egress6, tc.target)
			if tc.wantErr != "" {
				require.EqualError(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Same(t, tc.want, got)
		})
	}
}

// nonLoopbackIPv4Iface returns an interface with a non-loopback IPv4
// address, or skips the test when there is none.
func nonLoopbackIPv4Iface(t *testing.T) net.Interface {
	t.Helper()
	ifaces, err := net.Interfaces()
	require.NoError(t, err)
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok &&
				ipnet.IP.To4() != nil && !ipnet.IP.IsLoopback() {
				return iface
			}
		}
	}
	t.Skip("no interface with a non-loopback IPv4 address")
	return net.Interface{}
}

// TestBindEgress_IPv4 checks that an IPv4 dial gets the control and a
// source address of the network's kind on rt's interface.
func TestBindEgress_IPv4(t *testing.T) {
	rt := &route.Route{Family: netutil.FamilyV4, Iface: nonLoopbackIPv4Iface(t)}
	control := func(string, string, syscall.RawConn) error { return nil }

	tcs := []struct {
		network string
		want    net.Addr
	}{
		{"tcp", &net.TCPAddr{}},
		{"tcp4", &net.TCPAddr{}},
		{"udp", &net.UDPAddr{}},
		{"udp4", &net.UDPAddr{}},
		{"ip4", &net.IPAddr{}},
	}
	for _, tc := range tcs {
		t.Run(tc.network, func(t *testing.T) {
			var d net.Dialer
			require.NoError(
				t,
				bindEgress(&d, tc.network, net.ParseIP("192.0.2.1"), rt, control),
			)
			require.IsType(t, tc.want, d.LocalAddr)
			assert.NotNil(t, d.Control)
		})
	}
}

// TestBindEgress_IPv6 checks that an IPv6 dial gets the control and no
// source address, which the kernel picks.
func TestBindEgress_IPv6(t *testing.T) {
	rt := &route.Route{
		Family: netutil.FamilyV6,
		Iface:  net.Interface{Index: 999, Name: "eth999"},
	}
	called := false
	control := func(string, string, syscall.RawConn) error {
		called = true
		return nil
	}

	for _, network := range []string{"tcp", "tcp6", "udp6"} {
		t.Run(network, func(t *testing.T) {
			var d net.Dialer
			require.NoError(
				t,
				bindEgress(&d, network, net.ParseIP("2001:db8::1"), rt, control),
			)
			assert.Nil(t, d.LocalAddr)
			require.NotNil(t, d.Control)
			called = false
			require.NoError(t, d.Control("", "", nil))
			assert.True(t, called, "the dialer uses the given control")
		})
	}
}
