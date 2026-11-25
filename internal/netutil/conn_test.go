package netutil

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
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

func TestRelayOneWay_FirstRead(t *testing.T) {
	first := []byte("first chunk")
	later := []byte("later chunk")

	t.Run("passes the first read to onFirst and relays every byte", func(t *testing.T) {
		upstream, src := net.Pipe()
		dstEnd, client := net.Pipe()
		defer func() { _ = client.Close() }()

		go func() {
			// A pipe write returns once reads took all of it, so the first
			// read gets the first chunk alone.
			_, _ = upstream.Write(first)
			_, _ = upstream.Write(later)
			_ = upstream.Close()
		}()

		var seen [][]byte
		resCh := make(chan relayResult, 1)
		go relayOneWay(
			context.Background(), resCh, src, dstEnd, relayDirIn,
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
		resCh := make(chan relayResult, 1)
		go relayOneWay(
			context.Background(), resCh, srcEnd, dstEnd, relayDirIn,
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

		resCh := make(chan relayResult, 1)
		go relayOneWay(
			context.Background(), resCh, &failingConn{err: errReset}, dstEnd,
			relayDirIn, func([]byte) {},
		)

		res := <-resCh
		assert.ErrorIs(t, res.Err, errReset)
	})

	t.Run("a nil onFirst copies without inspecting", func(t *testing.T) {
		upstream, srcEnd := net.Pipe()
		dstEnd, client := net.Pipe()
		defer func() { _ = client.Close() }()
		go func() {
			_, _ = upstream.Write(first)
			_ = upstream.Close()
		}()

		resCh := make(chan relayResult, 1)
		go relayOneWay(
			context.Background(), resCh, srcEnd, dstEnd, relayDirIn, nil,
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

// tunnelPayloadSize spans many reads of the tunnel's buffer, and is not a
// multiple of it.
const tunnelPayloadSize = 1<<20 + 12345

// tcpPair returns the two ends of a loopback TCP connection.
func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()

	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	dialed, err := net.DialTCP("tcp", nil, ln.Addr().(*net.TCPAddr))
	require.NoError(t, err)
	t.Cleanup(func() { _ = dialed.Close() })
	accepted, err := ln.AcceptTCP()
	require.NoError(t, err)
	t.Cleanup(func() { _ = accepted.Close() })

	return dialed, accepted
}

// connPair returns the two ends of a connection: loopback TCP, or a
// net.Pipe, which has no kernel socket under it.
func connPair(t *testing.T, kind string) (net.Conn, net.Conn) {
	t.Helper()
	if kind == "tcp" {
		return tcpPair(t)
	}
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a, b
}

// patternBytes returns n bytes that don't repeat with a period of a power
// of two, so that a reordered or lost chunk shows.
func patternBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}

// relay runs relayOneWay from src to dst, sends payload into src from
// upstream and closes it, and returns what reached client and the result.
func relay(
	t *testing.T,
	upstream, src, dst, client net.Conn,
	payload []byte,
) ([]byte, relayResult) {
	t.Helper()

	go func() {
		_, _ = upstream.Write(payload)
		_ = upstream.Close()
	}()

	resCh := make(chan relayResult, 1)
	go relayOneWay(context.Background(), resCh, src, dst, relayDirIn, nil)

	got, err := io.ReadAll(client)
	require.NoError(t, err)
	return got, <-resCh
}

func TestRelayOneWay_RelaysEveryByte(t *testing.T) {
	payload := patternBytes(tunnelPayloadSize)

	for _, kind := range []string{"tcp", "pipe"} {
		t.Run(kind, func(t *testing.T) {
			upstream, src := connPair(t, kind)
			dst, client := connPair(t, kind)

			got, res := relay(t, upstream, src, dst, client, payload)

			assert.Equal(t, payload, got)
			assert.NoError(t, res.Err)
			assert.Equal(t, int64(len(payload)), res.Written)
		})
	}
}

func TestRelayOneWay_KeepsUDPDatagrams(t *testing.T) {
	loopback := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
	upstream, err := net.ListenUDP("udp", loopback)
	require.NoError(t, err)
	t.Cleanup(func() { _ = upstream.Close() })
	client, err := net.ListenUDP("udp", loopback)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	srcSock, err := net.DialUDP("udp", nil, upstream.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	dstSock, err := net.DialUDP("udp", nil, client.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	// The UDP handlers tunnel IdleTimeoutConns.
	src := NewIdleTimeoutConn(srcSock, time.Minute)
	dst := NewIdleTimeoutConn(dstSock, time.Minute)

	ctx, cancel := context.WithCancel(context.Background())
	resCh := make(chan relayResult, 1)
	go relayOneWay(ctx, resCh, src, dst, relayDirIn, nil)

	// Within the 9216-byte datagram limit of macOS.
	sizes := []int{1, 1400, 8000, 1400}
	buf := make([]byte, 64*1024)
	for _, size := range sizes {
		sent := patternBytes(size)
		_, err := upstream.WriteToUDP(sent, srcSock.LocalAddr().(*net.UDPAddr))
		require.NoError(t, err)

		require.NoError(t, client.SetReadDeadline(time.Now().Add(5*time.Second)))
		n, err := client.Read(buf)
		require.NoError(t, err)
		assert.Equal(t, sent, buf[:n], "a %d-byte datagram arrives whole", size)
	}

	cancel()
	res := <-resCh
	assert.NoError(t, res.Err)
	assert.Equal(t, int64(1+1400+8000+1400), res.Written)
}

func TestCopyConns_LeavesTCPToTCPToTheConns(t *testing.T) {
	payload := patternBytes(tunnelPayloadSize)
	upstream, srcEnd := tcpPair(t)
	dstEnd, client := tcpPair(t)
	// Both ends wrapped, as the SOCKS5 and TUN handlers have them.
	src := NewBufferedConn(srcEnd)
	dst := NewBufferedConn(dstEnd)

	go func() {
		_, _ = upstream.Write(payload)
		_ = upstream.Close()
	}()
	_, err := src.Peek(1)
	require.NoError(t, err)
	got := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(client)
		got <- b
	}()

	// The payload has no 0xff byte, so a buffer the copy used would show.
	buf := bytes.Repeat([]byte{0xff}, 32*1024)
	n, err := copyConns(dst, src, buf)
	_ = dstEnd.Close()

	require.NoError(t, err)
	assert.Equal(t, int64(len(payload)), n)
	assert.Equal(t, payload, <-got)
	// io.Copy of two *net.TCPConns reaches (*net.TCPConn).ReadFrom with the
	// source, which splices on Linux (spliceFrom in net/splice_linux.go).
	assert.Equal(t, bytes.Repeat([]byte{0xff}, len(buf)), buf,
		"the copy is left to the TCP conns, not done with buf")
}

// copyRecorder is a conn, like a gVisor conn, that has ReadFrom and
// WriteTo. It records whether they were called, and the size of the
// buffers its Read and Write were given.
type copyRecorder struct {
	net.Conn
	copyMethodCalled atomic.Bool
	maxRead          atomic.Int64
	maxWrite         atomic.Int64
}

func (c *copyRecorder) Read(p []byte) (int, error) {
	c.maxRead.Store(max(c.maxRead.Load(), int64(len(p))))
	return c.Conn.Read(p)
}

func (c *copyRecorder) Write(p []byte) (int, error) {
	c.maxWrite.Store(max(c.maxWrite.Load(), int64(len(p))))
	return c.Conn.Write(p)
}

func (c *copyRecorder) ReadFrom(r io.Reader) (int64, error) {
	c.copyMethodCalled.Store(true)
	return io.Copy(c.Conn, r)
}

func (c *copyRecorder) WriteTo(w io.Writer) (int64, error) {
	c.copyMethodCalled.Store(true)
	return io.Copy(w, c.Conn)
}

func TestCopyConns_CopiesWithTheBufferUnlessBothAreTCP(t *testing.T) {
	payload := patternBytes(tunnelPayloadSize)
	// Smaller than any buffer io.Copy or the net package allocates.
	const bufSize = 1000

	tcs := []struct {
		name string
		// conns returns the source and destination, the conn to send the
		// payload into, and the conn to read it from.
		conns func(t *testing.T) (src, dst *copyRecorder, srcConn, dstConn net.Conn,
			upstream, client net.Conn)
	}{
		{
			name: "pipe to pipe",
			conns: func(t *testing.T) (*copyRecorder, *copyRecorder, net.Conn, net.Conn,
				net.Conn, net.Conn,
			) {
				upstream, srcEnd := connPair(t, "pipe")
				dstEnd, client := connPair(t, "pipe")
				src := &copyRecorder{Conn: srcEnd}
				dst := &copyRecorder{Conn: dstEnd}
				return src, dst, src, dst, upstream, client
			},
		},
		{
			// As in TUN mode: a TCP remote and a gVisor client conn.
			name: "tcp to a conn with ReadFrom",
			conns: func(t *testing.T) (*copyRecorder, *copyRecorder, net.Conn, net.Conn,
				net.Conn, net.Conn,
			) {
				upstream, srcEnd := tcpPair(t)
				dstEnd, client := tcpPair(t)
				dst := &copyRecorder{Conn: dstEnd}
				return nil, dst, srcEnd, dst, upstream, client
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			src, dst, srcConn, dstConn, upstream, client := tc.conns(t)
			go func() {
				_, _ = upstream.Write(payload)
				_ = upstream.Close()
			}()
			got := make(chan []byte, 1)
			go func() {
				b, _ := io.ReadAll(client)
				got <- b
			}()

			n, err := copyConns(dstConn, srcConn, make([]byte, bufSize))
			_ = dstConn.Close()

			require.NoError(t, err)
			assert.Equal(t, int64(len(payload)), n)
			assert.Equal(t, payload, <-got)
			assert.False(t, dst.copyMethodCalled.Load(), "dst ReadFrom or WriteTo")
			assert.LessOrEqual(t, dst.maxWrite.Load(), int64(bufSize))
			if src != nil {
				assert.False(t, src.copyMethodCalled.Load(), "src ReadFrom or WriteTo")
				assert.Equal(t, int64(bufSize), src.maxRead.Load())
			}
		})
	}
}

func TestRelayOneWay_BufferedConn(t *testing.T) {
	payload := patternBytes(tunnelPayloadSize)

	t.Run("source gives its buffered bytes first", func(t *testing.T) {
		for _, kind := range []string{"tcp", "pipe"} {
			t.Run(kind, func(t *testing.T) {
				upstream, srcEnd := connPair(t, kind)
				dst, client := connPair(t, kind)
				src := NewBufferedConn(srcEnd)

				go func() {
					_, _ = upstream.Write(payload)
					_ = upstream.Close()
				}()
				// Peek fills the reader with what has arrived, as the
				// handlers do before they tunnel.
				peeked, err := src.Peek(5)
				require.NoError(t, err)
				require.Equal(t, payload[:5], peeked)
				require.Positive(t, src.r.Buffered())

				resCh := make(chan relayResult, 1)
				go relayOneWay(context.Background(), resCh, src, dst, relayDirOut, nil)

				got, err := io.ReadAll(client)
				require.NoError(t, err)
				assert.Equal(t, payload, got, "every byte, in order")
				res := <-resCh
				assert.NoError(t, res.Err)
				assert.Equal(t, int64(len(payload)), res.Written)
			})
		}
	})

	t.Run("destination gets every byte", func(t *testing.T) {
		upstream, src := tcpPair(t)
		dstEnd, client := tcpPair(t)
		dst := NewBufferedConn(dstEnd)

		got, res := relay(t, upstream, src, dst, client, payload)

		assert.Equal(t, payload, got)
		assert.NoError(t, res.Err)
	})
}

func TestBufferedConn_WriteBufferedTo(t *testing.T) {
	t.Run("writes the buffered bytes and reads no more", func(t *testing.T) {
		upstream, conn := net.Pipe()
		defer func() { _ = upstream.Close() }()
		b := NewBufferedConn(conn)
		go func() {
			_, _ = upstream.Write([]byte("hello"))
			_, _ = upstream.Write([]byte("world"))
		}()
		_, err := b.Peek(1)
		require.NoError(t, err)

		var w bytes.Buffer
		n, err := b.writeBufferedTo(&w)
		require.NoError(t, err)
		assert.Equal(t, 5, n)
		assert.Equal(t, "hello", w.String())
		assert.Zero(t, b.r.Buffered())

		rest := make([]byte, 5)
		_, err = io.ReadFull(conn, rest)
		require.NoError(t, err)
		assert.Equal(t, "world", string(rest), "the conn goes on after them")
	})

	t.Run("nothing buffered writes nothing", func(t *testing.T) {
		_, conn := net.Pipe()
		var w bytes.Buffer
		n, err := NewBufferedConn(conn).writeBufferedTo(&w)
		assert.NoError(t, err)
		assert.Zero(t, n)
		assert.Zero(t, w.Len())
	})

	t.Run("a short write keeps the rest buffered", func(t *testing.T) {
		upstream, conn := net.Pipe()
		defer func() { _ = upstream.Close() }()
		b := NewBufferedConn(conn)
		go func() { _, _ = upstream.Write([]byte("hello")) }()
		_, err := b.Peek(5)
		require.NoError(t, err)

		n, err := b.writeBufferedTo(&shortWriter{max: 2})
		assert.ErrorIs(t, err, io.ErrShortWrite)
		assert.Equal(t, 2, n)
		rest, err := b.Peek(3)
		require.NoError(t, err)
		assert.Equal(t, "llo", string(rest))
	})
}

// shortWriter takes at most max bytes of each write, without an error.
type shortWriter struct{ max int }

func (w *shortWriter) Write(p []byte) (int, error) { return min(len(p), w.max), nil }

// relayEnds returns the conns RelayBidirectional relays between, and the
// far ends a test drives them with: client and remote are the conns it
// takes, clientPeer and remotePeer the other ends of the sockets.
func relayEnds(t *testing.T) (client, clientPeer, remote, remotePeer net.Conn) {
	t.Helper()

	// Sockets, not pipes: a pipe whose own end is closed fails its read with
	// io.ErrClosedPipe, which is not a benign close.
	client, clientPeer = tcpPairConns(t)
	remote, remotePeer = tcpPairConns(t)
	t.Cleanup(func() {
		CloseConns(client, clientPeer, remote, remotePeer)
	})
	return client, clientPeer, remote, remotePeer
}

// tcpPairConns is tcpPair with its ends as net.Conns.
func tcpPairConns(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()

	a, b := tcpPair(t)
	return a, b
}

// awaitRelay returns the result of a relay that relayDone started, and fails
// the test when the relay does not end in time.
func awaitRelay(t *testing.T, done <-chan error) error {
	t.Helper()

	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("the relay did not end")
		return nil
	}
}

// relayDone runs RelayBidirectional in the background and returns a channel
// of its result.
func relayDone(
	ctx context.Context,
	logger zerolog.Logger,
	client, remote net.Conn,
	opts RelayOptions,
) <-chan error {
	done := make(chan error, 1)
	go func() { done <- RelayBidirectional(ctx, logger, client, remote, opts) }()
	return done
}

func TestRelayBidirectional(t *testing.T) {
	request := []byte("request bytes")
	reply := []byte("reply bytes")

	t.Run("relays both directions and logs their sizes", func(t *testing.T) {
		client, clientPeer, remote, remotePeer := relayEnds(t)
		var logs bytes.Buffer
		logger := zerolog.New(&logs).Level(zerolog.TraceLevel)

		done := relayDone(context.Background(), logger, client, remote, RelayOptions{})

		go func() { _, _ = clientPeer.Write(request) }()
		got := make([]byte, len(request))
		_, err := io.ReadFull(remotePeer, got)
		require.NoError(t, err)
		assert.Equal(t, request, got)

		go func() {
			_, _ = remotePeer.Write(reply)
			_ = remotePeer.Close()
		}()
		got, err = io.ReadAll(clientPeer)
		require.NoError(t, err)
		assert.Equal(t, reply, got)

		select {
		case err := <-done:
			assert.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("the relay outlived the remote's close")
		}

		var entry map[string]any
		require.NoError(t, json.Unmarshal(logs.Bytes(), &entry))
		assert.Equal(t, "tunnel closed", entry["message"])
		assert.EqualValues(t, len(request), entry["out"])
		assert.EqualValues(t, len(reply), entry["in"])
		assert.EqualValues(t, 0, entry["errs"])
		assert.Contains(t, entry, "took")
		assert.Contains(t, entry, "route")
	})

	t.Run("hands the first reply to OnFirstReply", func(t *testing.T) {
		client, clientPeer, remote, remotePeer := relayEnds(t)
		var seen [][]byte

		done := relayDone(context.Background(), zerolog.Nop(), client, remote, RelayOptions{
			OnFirstReply: func(b []byte) { seen = append(seen, append([]byte(nil), b...)) },
		})

		// A socket may join two writes into one read, so the second goes
		// out once the client has the first.
		_, err := remotePeer.Write(reply)
		require.NoError(t, err)
		first := make([]byte, len(reply))
		_, err = io.ReadFull(clientPeer, first)
		require.NoError(t, err)
		go func() {
			_, _ = remotePeer.Write(request)
			_ = remotePeer.Close()
		}()
		rest, err := io.ReadAll(clientPeer)
		require.NoError(t, err)
		assert.Equal(t, reply, first)
		assert.Equal(t, request, rest)
		require.NoError(t, awaitRelay(t, done))
		assert.Equal(t, [][]byte{reply}, seen, "only the first read is handed over")
	})

	t.Run("returns the first error without HandleErrs", func(t *testing.T) {
		errReset := errors.New("reset")
		clientEnd, clientPeer := tcpPairConns(t)
		failing, failingPeer := tcpPairConns(t)
		t.Cleanup(func() { CloseConns(clientEnd, clientPeer, failing, failingPeer) })

		err := RelayBidirectional(
			context.Background(), zerolog.Nop(), clientEnd,
			&failingConn{Conn: failing, err: errReset}, RelayOptions{},
		)
		assert.ErrorIs(t, err, errReset)
	})

	t.Run("returns what HandleErrs makes of the errors", func(t *testing.T) {
		errReset := errors.New("reset")
		errHandled := errors.New("handled")
		clientEnd, clientPeer := tcpPairConns(t)
		failing, failingPeer := tcpPairConns(t)
		t.Cleanup(func() { CloseConns(clientEnd, clientPeer, failing, failingPeer) })

		var got []error
		err := RelayBidirectional(
			context.Background(), zerolog.Nop(), clientEnd,
			&failingConn{Conn: failing, err: errReset}, RelayOptions{
				HandleErrs: func(errs []error) error {
					got = errs
					return errHandled
				},
			},
		)
		assert.ErrorIs(t, err, errHandled)
		require.NotEmpty(t, got)
		assert.ErrorIs(t, got[0], errReset)
	})

	t.Run("calls HandleErrs with no errors on a clean close", func(t *testing.T) {
		client, clientPeer, remote, remotePeer := relayEnds(t)

		called := false
		done := relayDone(context.Background(), zerolog.Nop(), client, remote, RelayOptions{
			HandleErrs: func(errs []error) error {
				called = true
				assert.Empty(t, errs)
				return nil
			},
		})

		_ = remotePeer.Close()
		_, err := io.ReadAll(clientPeer)
		require.NoError(t, err)
		require.NoError(t, awaitRelay(t, done))
		assert.True(t, called)
	})

	t.Run("returns and closes both conns when ctx is cancelled", func(t *testing.T) {
		client, clientPeer, remote, remotePeer := relayEnds(t)
		ctx, cancel := context.WithCancel(context.Background())

		done := relayDone(ctx, zerolog.Nop(), client, remote, RelayOptions{})
		cancel()

		select {
		case err := <-done:
			assert.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("the relay outlived the cancelled ctx")
		}

		_ = clientPeer.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err := clientPeer.Read(make([]byte, 1))
		assert.ErrorIs(t, err, io.EOF, "the client conn is closed")
		_ = remotePeer.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err = remotePeer.Read(make([]byte, 1))
		assert.ErrorIs(t, err, io.EOF, "the remote conn is closed")
	})
}
