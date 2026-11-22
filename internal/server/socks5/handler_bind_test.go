package socks5

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/proto"
)

// bindSession is a running BIND seen from the client side.
type bindSession struct {
	// client is the client's end of the control connection.
	client net.Conn
	// addr is the address advertised in the first reply.
	addr *net.TCPAddr
	// done is closed when Handle returns, with its result in err.
	done <-chan struct{}
	err  error
	// cancel cancels the context Handle runs with.
	cancel context.CancelFunc
	// logs holds what Handle logged.
	logs *bytes.Buffer
}

// startBind runs a BindHandler for req on a loopback control connection
// and reads the first reply, which must be a success.
func startBind(t *testing.T, req *proto.SOCKS5Request) *bindSession {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	client, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	srvConn, err := ln.Accept()
	require.NoError(t, err)

	logs := &bytes.Buffer{}
	h := NewBindHandler(zerolog.New(zerolog.SyncWriter(logs)))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	s := &bindSession{client: client, done: done, cancel: cancel, logs: logs}
	go func() {
		defer close(done)
		s.err = h.Handle(ctx, srvConn, req)
	}()
	t.Cleanup(func() {
		cancel()
		_ = client.Close()
		<-done
		_ = srvConn.Close()
	})

	code, addr := readBindReply(t, client)
	require.Equal(t, byte(proto.SOCKS5RCodeSuccess), code)
	s.addr = addr

	return s
}

// readBindReply returns the reply code and the address of the SOCKS5 reply
// on conn.
func readBindReply(t *testing.T, conn net.Conn) (byte, *net.TCPAddr) {
	t.Helper()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	// VER REP RSV ATYP(IPv4) ADDR(4) PORT(2)
	reply := make([]byte, 10)
	_, err := io.ReadFull(conn, reply)
	require.NoError(t, err)
	require.Equal(t, byte(proto.SOCKS5AddrTypeIPv4), reply[3])

	return reply[1], &net.TCPAddr{
		IP:   net.IP(reply[4:8]),
		Port: int(binary.BigEndian.Uint16(reply[8:10])),
	}
}

// connectIncoming connects to the BIND listener as the application server
// would, and reads the second reply from the client's control connection.
func (s *bindSession) connectIncoming(t *testing.T) (net.Conn, byte, *net.TCPAddr) {
	t.Helper()

	remote, err := net.Dial("tcp", s.addr.String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = remote.Close() })

	code, addr := readBindReply(t, s.client)
	return remote, code, addr
}

// wait returns Handle's result.
func (s *bindSession) wait(t *testing.T) error {
	t.Helper()
	select {
	case <-s.done:
		return s.err
	case <-time.After(5 * time.Second):
		t.Fatal("Handle did not return")
		return nil
	}
}

// assertListenerClosed asserts that nothing listens on s.addr anymore.
func (s *bindSession) assertListenerClosed(t *testing.T) {
	t.Helper()
	ln, err := net.ListenTCP("tcp", s.addr)
	if assert.NoError(t, err, "the bind listener must be closed") {
		_ = ln.Close()
	}
}

// readString reads exactly len(want) bytes from conn.
func readString(t *testing.T, conn net.Conn, want string) string {
	t.Helper()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	buf := make([]byte, len(want))
	_, err := io.ReadFull(conn, buf)
	require.NoError(t, err)
	return string(buf)
}

// assertEOF asserts that conn is closed by its peer.
func assertEOF(t *testing.T, conn net.Conn) {
	t.Helper()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, err := conn.Read(make([]byte, 1))
	assert.ErrorIs(t, err, io.EOF)
}

func TestBindHandler_Handle_RepliesAndRelay(t *testing.T) {
	s := startBind(t, &proto.SOCKS5Request{})

	// The first reply advertises a listener on the control connection's
	// local IP.
	assert.True(t, s.addr.IP.Equal(net.IPv4(127, 0, 0, 1)))
	assert.NotZero(t, s.addr.Port)

	// The second reply reports the connecting host's address.
	remote, code, addr := s.connectIncoming(t)
	assert.Equal(t, byte(proto.SOCKS5RCodeSuccess), code)
	assert.Equal(t, remote.LocalAddr().String(), addr.String())

	_, err := s.client.Write([]byte("ping"))
	require.NoError(t, err)
	assert.Equal(t, "ping", readString(t, remote, "ping"))

	_, err = remote.Write([]byte("pong"))
	require.NoError(t, err)
	assert.Equal(t, "pong", readString(t, s.client, "pong"))
}

func TestBindHandler_Handle_ExpectedHost(t *testing.T) {
	tcs := []struct {
		name     string
		ip       net.IP
		wantCode byte
	}{
		{"no address accepts any host", nil, proto.SOCKS5RCodeSuccess},
		{"unspecified address accepts any host", net.IPv4zero, proto.SOCKS5RCodeSuccess},
		{"matching address", net.IPv4(127, 0, 0, 1), proto.SOCKS5RCodeSuccess},
		{"other address", net.ParseIP("192.0.2.1"), proto.SOCKS5RCodeGenFailure},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			s := startBind(t, &proto.SOCKS5Request{IP: tc.ip})

			remote, code, _ := s.connectIncoming(t)
			assert.Equal(t, tc.wantCode, code)

			if tc.wantCode == proto.SOCKS5RCodeSuccess {
				return
			}
			// The connection from the unexpected host is closed and Handle
			// fails.
			assertEOF(t, remote)
			err := s.wait(t)
			assert.ErrorContains(t, err, "unexpected connecting host")
			s.assertListenerClosed(t)
		})
	}
}

func TestBindHandler_Handle_TunnelEnds(t *testing.T) {
	t.Run("remote closes", func(t *testing.T) {
		s := startBind(t, &proto.SOCKS5Request{})
		remote, code, _ := s.connectIncoming(t)
		require.Equal(t, byte(proto.SOCKS5RCodeSuccess), code)

		_ = remote.Close()

		assert.NoError(t, s.wait(t))
		assertEOF(t, s.client)
	})

	t.Run("client closes", func(t *testing.T) {
		s := startBind(t, &proto.SOCKS5Request{})
		remote, code, _ := s.connectIncoming(t)
		require.Equal(t, byte(proto.SOCKS5RCodeSuccess), code)

		_ = s.client.Close()

		assert.NoError(t, s.wait(t))
		assertEOF(t, remote)
	})
}

func TestBindHandler_Handle_EndsWhileWaiting(t *testing.T) {
	t.Run("client closes", func(t *testing.T) {
		s := startBind(t, &proto.SOCKS5Request{})

		_ = s.client.Close()

		err := s.wait(t)
		assert.ErrorIs(t, err, net.ErrClosed)
		s.assertListenerClosed(t)
		// The listener closing is reported as a failed accept.
		assert.Contains(t, s.logs.String(), `"level":"error"`)
		assert.Contains(t, s.logs.String(), "failed to accept incoming connection")
	})

	t.Run("context is cancelled", func(t *testing.T) {
		s := startBind(t, &proto.SOCKS5Request{})

		s.cancel()

		err := s.wait(t)
		assert.ErrorIs(t, err, context.Canceled)
		s.assertListenerClosed(t)
		assert.NotContains(t, s.logs.String(), "failed to accept incoming connection")
	})
}

// TestBindHandler_Handle_BytesBeforeSecondReply pins that bytes the client
// sends while BIND waits for the incoming connection are read off the
// control connection to watch for its closing, and are not relayed.
func TestBindHandler_Handle_BytesBeforeSecondReply(t *testing.T) {
	s := startBind(t, &proto.SOCKS5Request{})

	_, err := s.client.Write([]byte("early"))
	require.NoError(t, err)
	// Give the watch on the control connection time to read them.
	time.Sleep(300 * time.Millisecond)

	remote, code, _ := s.connectIncoming(t)
	require.Equal(t, byte(proto.SOCKS5RCodeSuccess), code)

	_, err = s.client.Write([]byte("late"))
	require.NoError(t, err)
	assert.Equal(t, "late", readString(t, remote, "late"))
}
