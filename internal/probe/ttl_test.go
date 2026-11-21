package probe

import (
	"context"
	"net"
	"net/netip"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// socketTTL returns the IPv4 TTL set on conn's socket.
func socketTTL(t *testing.T, conn syscall.Conn) int {
	t.Helper()
	raw, err := conn.SyscallConn()
	require.NoError(t, err)
	var ttl int
	var sockErr error
	require.NoError(t, raw.Control(func(fd uintptr) {
		ttl, sockErr = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL)
	}))
	require.NoError(t, sockErr)
	return ttl
}

func TestDialer_TCPSetsTTL(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	addr := netip.MustParseAddrPort(ln.Addr().String())

	// Loopback is 0 hops away, so a SYN with TTL 1 completes the
	// handshake.
	conn, err := dialer("tcp4")(context.Background(), 1, addr)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	assert.Equal(t, 1, socketTTL(t, conn.(*net.TCPConn)))

	def, err := dialer("tcp4")(context.Background(), 0, addr)
	require.NoError(t, err)
	defer func() { _ = def.Close() }()
	assert.NotEqual(t, 1, socketTTL(t, def.(*net.TCPConn)), "TTL 0 keeps the default")
}

func TestDialer_UDPSetsTTL(t *testing.T) {
	addr := netip.MustParseAddrPort("127.0.0.1:9")
	conn, err := dialer("udp4")(context.Background(), 7, addr)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	assert.Equal(t, 7, socketTTL(t, conn.(*net.UDPConn)))
}
