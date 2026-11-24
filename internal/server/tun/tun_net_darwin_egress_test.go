//go:build darwin

package tun

import (
	"context"
	"net"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/netutil"
)

// loopbackRoute returns a route through the loopback interface.
func loopbackRoute(t *testing.T) *netutil.Route {
	t.Helper()
	lo, err := net.InterfaceByName("lo0")
	require.NoError(t, err)
	return &netutil.Route{Iface: *lo}
}

// boundIf returns the IP_BOUND_IF of c's socket.
func boundIf(t *testing.T, c syscall.Conn) int {
	t.Helper()
	raw, err := c.SyscallConn()
	require.NoError(t, err)
	var index int
	var sockErr error
	require.NoError(t, raw.Control(func(fd uintptr) {
		index, sockErr = syscall.GetsockoptInt(
			int(fd),
			syscall.IPPROTO_IP,
			syscall.IP_BOUND_IF,
		)
	}))
	require.NoError(t, sockErr)
	return index
}

func TestEgressControl_Darwin(t *testing.T) {
	assert.Nil(t, EgressControl(nil, 0))
	assert.Nil(t, EgressControl(&netutil.Route{}, 0))

	route := loopbackRoute(t)
	control := EgressControl(route, 0)
	require.NotNil(t, control)

	lc := net.ListenConfig{Control: control}
	pc, err := lc.ListenPacket(context.Background(), "udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = pc.Close() }()
	assert.Equal(t, route.Iface.Index, boundIf(t, pc.(*net.UDPConn)))
}

// TestBindDialer_UsesEgressControl checks that dialed connections are
// pinned exactly as EgressControl pins the raw sockets of fake packets. A
// UDP connect sends nothing.
func TestBindDialer_UsesEgressControl(t *testing.T) {
	route, err := netutil.DiscoverRoute(nil)
	if err != nil {
		t.Skipf("no IPv4 default route: %v", err)
	}
	n := &tunSystemNetworkDarwin{defaultRoute: route}

	var d net.Dialer
	require.NoError(t, n.BindDialer(&d, "udp4", net.IPv4(192, 0, 2, 1)))
	require.NotNil(t, d.Control)

	c, err := d.Dial("udp4", "192.0.2.1:9")
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	assert.Equal(t, route.Iface.Index, boundIf(t, c.(*net.UDPConn)))
}
