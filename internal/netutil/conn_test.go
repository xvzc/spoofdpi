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

func TestIdleTimeoutConn_SetTimeout(t *testing.T) {
	t.Run("shorter timeout expires sooner", func(t *testing.T) {
		conn := NewIdleTimeoutConn(dialLoopbackUDP(t), time.Hour)
		conn.SetTimeout(50 * time.Millisecond)

		assert.Equal(t, 50*time.Millisecond, conn.Timeout())
		_, err := conn.Read(make([]byte, 1))
		assert.ErrorIs(t, err, os.ErrDeadlineExceeded)
		assert.True(t, conn.IsExpired(time.Now()))
	})

	t.Run("longer timeout restarts the idle period", func(t *testing.T) {
		conn := NewIdleTimeoutConn(dialLoopbackUDP(t), 50*time.Millisecond)
		conn.SetTimeout(time.Hour)

		time.Sleep(100 * time.Millisecond)
		assert.False(t, conn.IsExpired(time.Now()))
	})

	t.Run("zero timeout never expires", func(t *testing.T) {
		conn := NewIdleTimeoutConn(dialLoopbackUDP(t), 50*time.Millisecond)
		conn.SetTimeout(0)

		time.Sleep(100 * time.Millisecond)
		assert.False(t, conn.IsExpired(time.Now()))
		_, err := conn.Write([]byte{0})
		assert.NoError(t, err)
	})

	t.Run("expired connection stays expired", func(t *testing.T) {
		conn := NewIdleTimeoutConn(dialLoopbackUDP(t), 50*time.Millisecond)

		time.Sleep(100 * time.Millisecond)
		conn.SetTimeout(time.Hour)

		assert.True(t, conn.IsExpired(time.Now()))
	})

	t.Run("unblocks a pending read", func(t *testing.T) {
		conn := NewIdleTimeoutConn(dialLoopbackUDP(t), time.Hour)

		readErr := make(chan error, 1)
		go func() {
			_, err := conn.Read(make([]byte, 1))
			readErr <- err
		}()

		// Let the read block before the deadline moves.
		time.Sleep(50 * time.Millisecond)
		conn.SetTimeout(50 * time.Millisecond)

		select {
		case err := <-readErr:
			assert.ErrorIs(t, err, os.ErrDeadlineExceeded)
		case <-time.After(5 * time.Second):
			t.Fatal("read outlived the shorter timeout")
		}
	})
}
