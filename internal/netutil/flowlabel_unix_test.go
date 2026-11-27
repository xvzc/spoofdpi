//go:build darwin || freebsd || linux

package netutil

import (
	"bytes"
	"context"
	"errors"
	"net"
	"syscall"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// listenUDPRaw returns the raw conn of a UDP socket of network on addr. It
// skips the test when the address cannot be listened on.
func listenUDPRaw(t *testing.T, network, addr string) syscall.RawConn {
	t.Helper()
	pc, err := net.ListenPacket(network, addr)
	if err != nil {
		t.Skipf("listen %s %s: %v", network, addr, err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	rc, err := pc.(*net.UDPConn).SyscallConn()
	require.NoError(t, err)
	return rc
}

// setAutoFlowLabel sets IPV6_AUTOFLOWLABEL on c to v.
func setAutoFlowLabel(t *testing.T, c syscall.RawConn, v int) {
	t.Helper()
	var sockErr error
	require.NoError(t, c.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_AUTOFLOWLABEL, v)
	}))
	require.NoError(t, sockErr)
}

// autoFlowLabel returns IPV6_AUTOFLOWLABEL of c.
func autoFlowLabel(t *testing.T, c syscall.RawConn) int {
	t.Helper()
	var v int
	var sockErr error
	require.NoError(t, c.Control(func(fd uintptr) {
		v, sockErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_AUTOFLOWLABEL)
	}))
	require.NoError(t, sockErr)
	return v
}

func TestDisableAutoFlowLabel_IPv6(t *testing.T) {
	rc := listenUDPRaw(t, "udp6", "[::1]:0")
	setAutoFlowLabel(t, rc, 1)

	require.NoError(t, DisableAutoFlowLabel("udp6", rc))
	assert.Equal(t, 0, autoFlowLabel(t, rc))
}

func TestDisableAutoFlowLabel_IPv4(t *testing.T) {
	rc := listenUDPRaw(t, "udp4", "127.0.0.1:0")

	// An IPv6-level option on an AF_INET socket would fail.
	assert.NoError(t, DisableAutoFlowLabel("udp4", rc),
		"an IPv4 socket is left as it is")
}

func TestNoAutoFlowLabelControl_LogsFailure(t *testing.T) {
	pc, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skipf("listen udp6 [::1]: %v", err)
	}
	rc, err := pc.(*net.UDPConn).SyscallConn()
	require.NoError(t, err)
	require.NoError(t, pc.Close())

	var buf bytes.Buffer
	control := NoAutoFlowLabelControl(zerolog.New(&buf).Level(zerolog.DebugLevel))

	assert.NoError(
		t,
		control("udp6", "[::1]:443", rc),
		"a failure does not fail the socket",
	)
	assert.Contains(t, buf.String(), "failed to turn the automatic IPv6 flow label off")
}

func TestDialFastest_ControlRunsAfterBind(t *testing.T) {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("listen tcp6 [::1]: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	var bindControlRan bool
	bind := func(d *net.Dialer, _ string, _ net.IP) error {
		// It runs on the dial's goroutine, so it reports by its error.
		d.Control = func(_, _ string, c syscall.RawConn) error {
			bindControlRan = true
			var sockErr error
			err := c.Control(func(fd uintptr) {
				sockErr = unix.SetsockoptInt(
					int(fd), unix.IPPROTO_IPV6, unix.IPV6_AUTOFLOWLABEL, 1,
				)
			})
			return errors.Join(err, sockErr)
		}
		return nil
	}
	dst := &Destination{
		Addrs: []net.IP{net.IPv6loopback},
		Port:  ln.Addr().(*net.TCPAddr).Port,
	}

	conn, err := DialFastest(context.Background(), dst, "tcp", DialOptions{
		Bind:    bind,
		Control: NoAutoFlowLabelControl(zerolog.Nop()),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	assert.True(t, bindControlRan, "the control of Bind still runs")
	rc, err := conn.(*net.TCPConn).SyscallConn()
	require.NoError(t, err)
	assert.Equal(t, 0, autoFlowLabel(t, rc), "Control runs after the control of Bind")
}
