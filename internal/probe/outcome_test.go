package probe

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// outcomeOf writes a stand-in ClientHello on a loopback connection whose
// server reads it all, then acts, and returns the outcome read.
func outcomeOf(t *testing.T, act func(server net.Conn)) outcome {
	t.Helper()
	client, server := loopbackPair(t)
	go func() {
		buf := make([]byte, 6)
		_, _ = io.ReadFull(server, buf)
		act(server)
	}()
	_, err := client.Write([]byte{0x16, 3, 1, 0, 1, 1})
	require.NoError(t, err)
	require.NoError(t, client.SetDeadline(time.Now().Add(300*time.Millisecond)))
	return readOutcome(client)
}

func TestReadOutcome(t *testing.T) {
	tcs := []struct {
		name string
		act  func(server net.Conn)
		want outcome
	}{
		{
			name: "server hello",
			act: func(s net.Conn) {
				_, _ = s.Write([]byte{0x16, 3, 3, 0, 90, 0x02, 0, 0, 86})
			},
			want: outcome{kind: outPass},
		},
		{
			name: "alert",
			act:  func(s net.Conn) { _, _ = s.Write([]byte{0x15, 3, 3, 0, 2, 2, 112}) },
			want: outcome{kind: outOther, detail: "TLS alert 112", serverReplied: true},
		},
		{
			name: "short alert then close",
			act: func(s net.Conn) {
				_, _ = s.Write([]byte{0x15, 3, 3})
				_ = s.Close()
			},
			want: outcome{kind: outOther, detail: "TLS alert", serverReplied: true},
		},
		{
			name: "http reply",
			act:  func(s net.Conn) { _, _ = s.Write([]byte("HTTP/1.1 403 Forbidden\r\n")) },
			want: outcome{kind: outOther, detail: "unexpected reply"},
		},
		{
			name: "rst",
			act: func(s net.Conn) {
				_ = s.(*net.TCPConn).SetLinger(0)
				_ = s.Close()
			},
			want: outcome{kind: outRST},
		},
		{
			name: "silent",
			act:  func(net.Conn) {},
			want: outcome{kind: outDrop},
		},
		{
			name: "fin",
			act:  func(s net.Conn) { _ = s.Close() },
			want: outcome{kind: outOther, detail: "closed"},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, outcomeOf(t, tc.act))
		})
	}
}

func TestErrOutcome(t *testing.T) {
	sysErr := func(errno syscall.Errno) error {
		return &net.OpError{
			Op:  "write",
			Net: "tcp4",
			Err: os.NewSyscallError("write", errno),
		}
	}
	assert.Equal(t, outcome{kind: outRST}, errOutcome(sysErr(syscall.EPIPE)))
	assert.Equal(t, outcome{kind: outRST}, errOutcome(sysErr(syscall.ECONNRESET)))
	assert.Equal(t, outcome{kind: outDrop}, errOutcome(context.DeadlineExceeded))
	assert.Equal(t,
		outcome{kind: outOther, detail: syscall.EHOSTUNREACH.Error()},
		errOutcome(sysErr(syscall.EHOSTUNREACH)))
	assert.Equal(t,
		outcome{kind: outRST, connectFailed: true},
		dialOutcome(sysErr(syscall.ECONNREFUSED)))
	assert.Equal(
		t,
		localOutcome("local error EMFILE"),
		dialOutcome(sysErr(syscall.EMFILE)),
		"a local error is not a failed connection",
	)
	assert.Equal(
		t,
		"answered",
		outcome{kind: outOther, serverReplied: true}.residualClass(),
	)
	assert.Equal(t, "answered", outcome{kind: outPass}.residualClass())
	assert.Equal(t, "closed", outcome{kind: outOther, detail: "closed"}.residualClass())
	assert.Equal(t, "silent", outcome{kind: outDrop}.residualClass())
}

func TestWriteAfterRST(t *testing.T) {
	client, server := loopbackPair(t)
	_ = server.(*net.TCPConn).SetLinger(0)
	_ = server.Close()
	require.NoError(t, client.SetDeadline(time.Now().Add(time.Second)))
	// The first write may still succeed; a later one fails once the RST is
	// in.
	var o outcome
	for range 20 {
		if _, err := client.Write([]byte("x")); err != nil {
			o = errOutcome(err)
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	assert.Equal(t, outcome{kind: outRST}, o)
}

// serverHelloRecord returns a record holding a ServerHello that echoes
// sid.
func serverHelloRecord(sid []byte) []byte {
	// The handshake type and length, then the version and the random.
	body := []byte{0x02, 0, 0, 0, 3, 3}
	body = append(body, make([]byte, 32)...)
	body = append(body, byte(len(sid)))
	body = append(body, sid...)
	// The cipher suite, the compression method and no extensions.
	body = append(body, 0x13, 0x01, 0, 0, 0)
	n := len(body) - 4
	body[1], body[2], body[3] = byte(n>>16), byte(n>>8), byte(n)
	rec := []byte{0x16, 3, 3, 0, 0}
	binary.BigEndian.PutUint16(rec[3:], uint16(len(body)))
	return append(rec, body...)
}

func TestReadHello(t *testing.T) {
	ids := &helloCheck{real: bytes32(1), fake: bytes32(2), linger: 200 * time.Millisecond}
	other := bytes32(3)
	certificate := []byte{0x16, 3, 3, 0, 4, 0x0b, 0, 0, 0}
	tcs := []struct {
		name string
		act  func(server net.Conn)
		want outcome
	}{
		{
			name: "real session ID",
			act:  func(s net.Conn) { _, _ = s.Write(serverHelloRecord(ids.real)) },
			want: outcome{kind: outPass},
		},
		{
			name: "fake session ID",
			act:  func(s net.Conn) { _, _ = s.Write(serverHelloRecord(ids.fake)) },
			want: outcome{
				kind:          outOther,
				detail:        "answered fake",
				serverReplied: true,
				answeredFake:  true,
			},
		},
		{
			name: "other session ID, then silence",
			act: func(s net.Conn) {
				_, _ = s.Write(append(serverHelloRecord(other), certificate...))
			},
			want: outcome{kind: outPass},
		},
		{
			name: "other session ID, then an alert",
			act: func(s net.Conn) {
				_, _ = s.Write(serverHelloRecord(other))
				_, _ = s.Write(certificate)
				_, _ = s.Write([]byte{0x15, 3, 3, 0, 2, 2, 10})
			},
			want: outcome{kind: outOther, detail: "TLS alert 10", serverReplied: true},
		},
		{
			name: "other session ID, then a close",
			act: func(s net.Conn) {
				_, _ = s.Write(serverHelloRecord(other))
				_ = s.Close()
			},
			want: outcome{kind: outOther, detail: "closed"},
		},
		{
			name: "other session ID, then a reset",
			act: func(s net.Conn) {
				_, _ = s.Write(serverHelloRecord(other))
				time.Sleep(20 * time.Millisecond)
				_ = s.(*net.TCPConn).SetLinger(0)
				_ = s.Close()
			},
			want: outcome{kind: outRST},
		},
		{
			name: "alert",
			act:  func(s net.Conn) { _, _ = s.Write([]byte{0x15, 3, 3, 0, 2, 2, 112}) },
			want: outcome{kind: outOther, detail: "TLS alert 112", serverReplied: true},
		},
		{
			name: "fin",
			act:  func(s net.Conn) { _ = s.Close() },
			want: outcome{kind: outOther, detail: "closed"},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			client, server := loopbackPair(t)
			go tc.act(server)
			require.NoError(t, client.SetDeadline(time.Now().Add(time.Second)))
			start := time.Now()
			assert.Equal(t, tc.want, readHello(context.Background(), client, ids))
			assert.Less(t, time.Since(start), 900*time.Millisecond, "within the linger")
		})
	}
}

// TestReadHello_LingerBounds checks that the linger after a ServerHello
// with another session ID ends with ctx, and never runs past the
// attempt's deadline.
func TestReadHello_LingerBounds(t *testing.T) {
	other := serverHelloRecord(bytes32(3))
	check := func(deadline time.Time) *helloCheck {
		return &helloCheck{
			real: bytes32(1), fake: bytes32(2), linger: 5 * time.Second, deadline: deadline,
		}
	}

	t.Run("cancelled", func(t *testing.T) {
		client, server := loopbackPair(t)
		_, _ = server.Write(other)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		start := time.Now()
		assert.Equal(t, outcome{kind: outPass}, readHello(ctx, client, check(time.Time{})))
		assert.Less(t, time.Since(start), time.Second)
	})

	t.Run("cancelled while lingering", func(t *testing.T) {
		client, server := loopbackPair(t)
		_, _ = server.Write(other)
		ctx, cancel := context.WithCancel(context.Background())
		// As dialForHello does.
		stop := context.AfterFunc(ctx, func() { _ = client.SetDeadline(time.Unix(1, 0)) })
		defer stop()
		time.AfterFunc(100*time.Millisecond, cancel)
		start := time.Now()
		readHello(ctx, client, check(time.Time{}))
		assert.Less(t, time.Since(start), time.Second)
	})

	t.Run("deadline before the linger ends", func(t *testing.T) {
		client, server := loopbackPair(t)
		_, _ = server.Write(other)
		start := time.Now()
		got := readHello(
			context.Background(),
			client,
			check(start.Add(150*time.Millisecond)),
		)
		assert.Equal(t, outcome{kind: outPass}, got)
		assert.Less(t, time.Since(start), time.Second)
	})
}

func bytes32(b byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}
