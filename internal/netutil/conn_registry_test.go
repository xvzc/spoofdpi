package netutil

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// dialLoopbackUDP returns a UDP socket connected to a local listener.
func dialLoopbackUDP(t *testing.T) net.Conn {
	t.Helper()

	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	conn, err := net.DialUDP("udp", nil, ln.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	return conn
}

// testKey returns a distinct registry key per port.
func testKey(port int) NATKey {
	ip := net.IPv4(127, 0, 0, 1)
	return NewNATKey(ip, port, ip, 9)
}

func TestConnRegistry_Store_PerConnTimeout(t *testing.T) {
	p := NewConnRegistry[NATKey](8)

	short := p.Store(testKey(1), dialLoopbackUDP(t), 50*time.Millisecond)
	long := p.Store(testKey(2), dialLoopbackUDP(t), time.Hour)

	assert.Equal(t, 50*time.Millisecond, short.Timeout)
	assert.Equal(t, time.Hour, long.Timeout)

	// The read deadline follows the connection's own timeout.
	_, err := short.Read(make([]byte, 1))
	assert.ErrorIs(t, err, os.ErrDeadlineExceeded)

	now := time.Now()
	assert.True(t, short.IsExpired(now))
	assert.False(t, long.IsExpired(now))
}

func TestConnRegistry_EvictExpired(t *testing.T) {
	p := NewConnRegistry[NATKey](8)

	shortRaw := dialLoopbackUDP(t)
	longRaw := dialLoopbackUDP(t)
	p.Store(testKey(1), shortRaw, 50*time.Millisecond)
	p.Store(testKey(2), longRaw, time.Hour)
	p.Store(testKey(3), dialLoopbackUDP(t), 0)

	time.Sleep(100 * time.Millisecond)
	p.evictExpired()

	assert.False(t, p.Has(testKey(1)))
	assert.True(t, p.Has(testKey(2)))
	assert.True(t, p.Has(testKey(3)))

	// Eviction closes the connection.
	_, err := shortRaw.Write([]byte{0})
	assert.ErrorIs(t, err, net.ErrClosed)
	_, err = longRaw.Write([]byte{0})
	assert.NoError(t, err)
}

func TestConnRegistry_EvictIf(t *testing.T) {
	p := NewConnRegistry[NATKey](8)

	oldRaw := dialLoopbackUDP(t)
	newRaw := dialLoopbackUDP(t)
	oldConn := p.Store(testKey(1), oldRaw, time.Hour)
	newConn := p.Store(testKey(1), newRaw, time.Hour)

	// The replaced connection can't evict its replacement.
	assert.False(t, p.EvictIf(testKey(1), oldConn))
	assert.True(t, p.Has(testKey(1)))
	_, err := newRaw.Write([]byte{0})
	assert.NoError(t, err)

	assert.True(t, p.EvictIf(testKey(1), newConn))
	assert.False(t, p.Has(testKey(1)))
	_, err = newRaw.Write([]byte{0})
	assert.ErrorIs(t, err, net.ErrClosed)
}

func TestConnRegistry_CloseReplacedConn(t *testing.T) {
	p := NewConnRegistry[NATKey](8)

	oldConn := p.Store(testKey(1), dialLoopbackUDP(t), time.Hour)
	p.Store(testKey(1), dialLoopbackUDP(t), time.Hour)

	// Closing the replaced wrapper leaves the newer connection in place.
	_ = oldConn.Close()
	assert.True(t, p.Has(testKey(1)))
}
