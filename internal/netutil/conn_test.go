package netutil

import (
	"context"
	"errors"
	"io"
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

// writeToConn records that the copy after the first read used the source's
// own WriteTo, which is how a TCP source gets the kernel splice. A wrapper
// that hides WriteTo would not be recorded.
type writeToConn struct {
	net.Conn
	writeToCalled chan struct{}
}

func (c *writeToConn) WriteTo(w io.Writer) (int64, error) {
	close(c.writeToCalled)
	return io.Copy(w, c.Conn)
}

func TestTunnelConnsFirstRead(t *testing.T) {
	first := []byte("first chunk")
	later := []byte("later chunk")

	t.Run("passes the first read to onFirst and relays every byte", func(t *testing.T) {
		upstream, srcEnd := net.Pipe()
		dstEnd, client := net.Pipe()
		defer func() { _ = client.Close() }()
		src := &writeToConn{Conn: srcEnd, writeToCalled: make(chan struct{})}

		go func() {
			_, _ = upstream.Write(first)
			// Wait for the copy to take over before the later chunk.
			<-src.writeToCalled
			_, _ = upstream.Write(later)
			_ = upstream.Close()
		}()

		var seen [][]byte
		resCh := make(chan TransferResult, 1)
		go TunnelConnsFirstRead(
			context.Background(), resCh, src, dstEnd, TunnelDirIn,
			func(b []byte) { seen = append(seen, append([]byte(nil), b...)) },
		)

		got, err := io.ReadAll(client)
		require.NoError(t, err)
		assert.Equal(t, append(append([]byte(nil), first...), later...), got)

		res := <-resCh
		require.NoError(t, res.Err)
		assert.Equal(t, int64(len(first)+len(later)), res.Written,
			"the first read counts")
		assert.Equal(t, [][]byte{first}, seen, "only the first read is inspected")
	})

	t.Run("a source that closes before sending is not an error", func(t *testing.T) {
		upstream, srcEnd := net.Pipe()
		dstEnd, client := net.Pipe()
		defer func() { _ = client.Close() }()
		_ = upstream.Close()

		called := false
		resCh := make(chan TransferResult, 1)
		go TunnelConnsFirstRead(
			context.Background(), resCh, srcEnd, dstEnd, TunnelDirIn,
			func([]byte) { called = true },
		)

		got, err := io.ReadAll(client)
		require.NoError(t, err)
		assert.Empty(t, got)
		res := <-resCh
		assert.NoError(t, res.Err)
		assert.Zero(t, res.Written)
		assert.False(t, called)
	})

	t.Run("a source reset before sending is an error", func(t *testing.T) {
		errReset := errors.New("reset")
		dstEnd, client := net.Pipe()
		defer func() { _ = client.Close() }()

		resCh := make(chan TransferResult, 1)
		go TunnelConnsFirstRead(
			context.Background(), resCh, &failingConn{err: errReset}, dstEnd,
			TunnelDirIn, func([]byte) {},
		)

		res := <-resCh
		assert.ErrorIs(t, res.Err, errReset)
	})

	t.Run("a nil onFirst copies like TunnelConns", func(t *testing.T) {
		upstream, srcEnd := net.Pipe()
		dstEnd, client := net.Pipe()
		defer func() { _ = client.Close() }()
		go func() {
			_, _ = upstream.Write(first)
			_ = upstream.Close()
		}()

		resCh := make(chan TransferResult, 1)
		go TunnelConnsFirstRead(
			context.Background(), resCh, srcEnd, dstEnd, TunnelDirIn, nil,
		)

		got, err := io.ReadAll(client)
		require.NoError(t, err)
		assert.Equal(t, first, got)
		assert.Equal(t, int64(len(first)), (<-resCh).Written)
	})
}

// failingConn fails every read with err.
type failingConn struct {
	net.Conn
	err error
}

func (c *failingConn) Read([]byte) (int, error) { return 0, c.err }
func (c *failingConn) Close() error             { return nil }
