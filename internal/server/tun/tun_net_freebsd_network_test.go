//go:build network && freebsd

package tun

import (
	"context"
	"net"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// TestEgressControlLive_IPv6 opens an IPv6 socket with EgressControl and
// checks that its SO_SETFIB, read back, is the FIB: the FIB pins IPv6
// sockets as it pins IPv4 ones.
func TestEgressControlLive_IPv6(t *testing.T) {
	fibs, err := unix.SysctlUint32("net.fibs")
	require.NoError(t, err)
	if fibs < 2 {
		t.Skip("the kernel has one FIB (net.fibs)")
	}
	fib := int(fibs) - 1
	control := EgressControl(nil, fib)
	require.NotNil(t, control)

	lc := net.ListenConfig{Control: control}
	conn, err := lc.ListenPacket(context.Background(), "udp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 on lo0: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	raw, err := conn.(syscall.Conn).SyscallConn()
	require.NoError(t, err)
	var got int
	var sockErr error
	require.NoError(t, raw.Control(func(fd uintptr) {
		got, sockErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SETFIB)
	}))
	require.NoError(t, sockErr)
	assert.Equal(t, fib, got, "SO_SETFIB of the socket")
}
