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
	"github.com/xvzc/spoofdpi/internal/route"
	"golang.org/x/sys/unix"
)

// internetRoute returns the IPv4 route of the interface the kernel routes
// the internet through, as TUN mode pins its sockets to, or skips the test
// when there is none.
func internetRoute(t *testing.T) *route.Route {
	t.Helper()
	iface, localIP, err := route.InternetInterface()
	if err != nil {
		t.Skipf("no IPv4 default route: %v", err)
	}
	return &route.Route{Family: netutil.FamilyV4, Iface: *iface, LocalIP: localIP}
}

// loopbackRoute returns a route of fam through the loopback interface.
func loopbackRoute(t *testing.T, fam netutil.Family) *route.Route {
	t.Helper()
	lo, err := net.InterfaceByName("lo0")
	require.NoError(t, err)
	return &route.Route{Family: fam, Iface: *lo}
}

// boundIf returns the IP_BOUND_IF of c's socket.
func boundIf(t *testing.T, c syscall.Conn) int {
	t.Helper()
	return getsockoptInt(t, c, unix.IPPROTO_IP, unix.IP_BOUND_IF)
}

// boundIf6 returns the IPV6_BOUND_IF of c's socket.
func boundIf6(t *testing.T, c syscall.Conn) int {
	t.Helper()
	return getsockoptInt(t, c, unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF)
}

// getsockoptInt returns the socket option opt at level of c's socket.
func getsockoptInt(t *testing.T, c syscall.Conn, level, opt int) int {
	t.Helper()
	raw, err := c.SyscallConn()
	require.NoError(t, err)
	var value int
	var sockErr error
	require.NoError(t, raw.Control(func(fd uintptr) {
		value, sockErr = unix.GetsockoptInt(int(fd), level, opt)
	}))
	require.NoError(t, sockErr)
	return value
}

// listenUDP opens a UDP socket on address with control.
func listenUDP(
	t *testing.T,
	network, address string,
	control func(network, address string, c syscall.RawConn) error,
) *net.UDPConn {
	t.Helper()
	lc := net.ListenConfig{Control: control}
	pc, err := lc.ListenPacket(context.Background(), network, address)
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })
	return pc.(*net.UDPConn)
}

// listenUDP6Loopback opens a UDP socket on [::1] with control, or skips
// the test when loopback IPv6 is unavailable.
func listenUDP6Loopback(
	t *testing.T,
	control func(network, address string, c syscall.RawConn) error,
) *net.UDPConn {
	t.Helper()
	probe, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 on lo0: %v", err)
	}
	_ = probe.Close()
	return listenUDP(t, "udp6", "[::1]:0", control)
}

func TestEgressControl_Darwin(t *testing.T) {
	assert.Nil(t, EgressControl(nil, 0))
	assert.Nil(t, EgressControl(&route.Route{}, 0))

	t.Run("ipv4", func(t *testing.T) {
		rt := loopbackRoute(t, netutil.FamilyV4)
		control := EgressControl(rt, 0)
		require.NotNil(t, control)

		pc := listenUDP(t, "udp4", "127.0.0.1:0", control)
		assert.Equal(t, rt.Iface.Index, boundIf(t, pc))
	})

	t.Run("ipv6", func(t *testing.T) {
		rt := loopbackRoute(t, netutil.FamilyV6)
		control := EgressControl(rt, 0)
		require.NotNil(t, control)

		pc := listenUDP6Loopback(t, control)
		assert.Equal(t, rt.Iface.Index, boundIf6(t, pc))
	})

	// The socket's network decides the option, whatever rt's family.
	for _, fam := range []netutil.Family{0, netutil.FamilyV4} {
		t.Run("ipv6 socket, route family "+fam.String(), func(t *testing.T) {
			rt := loopbackRoute(t, fam)
			pc := listenUDP6Loopback(t, EgressControl(rt, 0))
			assert.Equal(t, rt.Iface.Index, boundIf6(t, pc))
		})
	}
}

func TestSocketFamily(t *testing.T) {
	tcs := []struct {
		network  string
		fallback netutil.Family
		want     netutil.Family
	}{
		{"tcp4", netutil.FamilyV6, netutil.FamilyV4},
		{"udp4", netutil.FamilyV6, netutil.FamilyV4},
		{"ip4", netutil.FamilyV6, netutil.FamilyV4},
		{"ip4:255", netutil.FamilyV6, netutil.FamilyV4},
		{"tcp6", netutil.FamilyV4, netutil.FamilyV6},
		{"udp6", netutil.FamilyV4, netutil.FamilyV6},
		{"ip6:tcp", netutil.FamilyV4, netutil.FamilyV6},
		{"tcp", netutil.FamilyV6, netutil.FamilyV6},
		{"", netutil.FamilyV4, netutil.FamilyV4},
		{"ip:6", 0, 0},
	}
	for _, tc := range tcs {
		t.Run(tc.network, func(t *testing.T) {
			assert.Equal(t, tc.want, socketFamily(tc.network, tc.fallback))
		})
	}
}

// TestBindDialer_UsesEgressControl checks that dialed connections are
// pinned exactly as EgressControl pins the raw sockets of fake packets. A
// UDP connect sends nothing.
func TestBindDialer_UsesEgressControl(t *testing.T) {
	rt := internetRoute(t)
	n := &tunSystemNetworkDarwin{egress4: rt}

	var d net.Dialer
	require.NoError(t, n.BindDialer(&d, "udp4", net.IPv4(192, 0, 2, 1)))
	require.NotNil(t, d.Control)
	require.IsType(t, &net.UDPAddr{}, d.LocalAddr, "IPv4 pins the source address")

	c, err := d.Dial("udp4", "192.0.2.1:9")
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	assert.Equal(t, rt.Iface.Index, boundIf(t, c.(*net.UDPConn)))
}

// TestBindDialer_IPv6 checks that an IPv6 dial is pinned to the IPv6
// egress with IPV6_BOUND_IF and leaves the source address to the kernel.
// The control is checked on a socket of its own: this host may have no
// IPv6 route to dial through.
func TestBindDialer_IPv6(t *testing.T) {
	egress4 := &route.Route{
		Family: netutil.FamilyV4,
		Iface:  net.Interface{Index: 999, Name: "en999"},
	}
	egress6 := loopbackRoute(t, netutil.FamilyV6)
	n := &tunSystemNetworkDarwin{egress4: egress4, egress6: egress6}

	for _, network := range []string{"tcp", "tcp6", "udp6"} {
		t.Run(network, func(t *testing.T) {
			var d net.Dialer
			require.NoError(t, n.BindDialer(&d, network, net.ParseIP("2001:db8::1")))
			assert.Nil(t, d.LocalAddr, "the kernel picks the source address")
			require.NotNil(t, d.Control)

			pc := listenUDP6Loopback(t, d.Control)
			assert.Equal(t, egress6.Iface.Index, boundIf6(t, pc))
		})
	}
}

func TestBindDialer_NoEgressForFamily(t *testing.T) {
	n := &tunSystemNetworkDarwin{egress4: loopbackRoute(t, netutil.FamilyV4)}
	var d net.Dialer
	err := n.BindDialer(&d, "tcp", net.ParseIP("2001:db8::1"))
	require.EqualError(t, err, "no ipv6 egress for target 2001:db8::1")
	assert.Nil(t, d.Control)
	assert.Nil(t, d.LocalAddr)
}
