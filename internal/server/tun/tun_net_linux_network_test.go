//go:build network && linux

package tun

import (
	"context"
	"net"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/route"
	"github.com/xvzc/spoofdpi/internal/testutil"
)

// TestEgressControlLive_Mark_RequireRoot opens a socket with EgressControl
// pinned to lo and checks that its SO_MARK, read back, is egressFwmark, the
// mark that lets TUN mode's own sockets pass its capture rule.
func TestEgressControlLive_Mark_RequireRoot(t *testing.T) {
	testutil.RequireRoot(t)
	lo, err := net.InterfaceByName("lo")
	require.NoError(t, err)
	control := EgressControl(&route.Route{Iface: *lo}, 0)
	require.NotNil(t, control)

	lc := net.ListenConfig{Control: control}
	conn, err := lc.ListenPacket(context.Background(), "udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	sc, ok := conn.(syscall.Conn)
	require.True(t, ok)
	raw, err := sc.SyscallConn()
	require.NoError(t, err)
	var mark int
	var sockErr error
	require.NoError(t, raw.Control(func(fd uintptr) {
		mark, sockErr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK)
	}))
	require.NoError(t, sockErr)
	assert.Equal(t, egressFwmark, mark, "SO_MARK of the socket")
}
