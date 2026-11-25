package netutil

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/rs/zerolog"
)

// relayDir is the direction of one half of a relay.
type relayDir int

const (
	relayDirOut relayDir = iota // client -> remote
	relayDirIn                  // remote -> client
)

// relayResult holds the result of one direction of a relay.
type relayResult struct {
	Written int64
	Dir     relayDir
	Err     error
}

// bufferPool is a package-level pool of 32KB buffers that the relays copy
// with, to reduce memory allocations and GC pressure in the hot path. A
// relay between two *net.TCPConns doesn't use it (see copyConns).
var bufferPool = sync.Pool{
	New: func() any {
		// We allocate a pointer to a byte slice.
		// 32KB is the default buffer size for io.Copy.
		b := make([]byte, 32*1024)
		return &b
	},
}

// relayOneWay copies data from src to dst, and sends the result to resCh
// upon completion. When onFirst is not nil, it hands the bytes of the first
// read from src to onFirst, before it writes them to dst; onFirst must not
// change or keep them. It copies the rest between the conns that src and
// dst wrap, when they are BufferedConns, so that on Linux a TCP src and dst
// keep the kernel splice.
// It filters out benign errors like EOF, pipe closed, or read timeouts (for UDP).
func relayOneWay(
	ctx context.Context,
	resCh chan<- relayResult,
	src net.Conn,
	dst net.Conn,
	dir relayDir,
	onFirst func(first []byte),
) {
	var once sync.Once
	closeOnce := func() {
		once.Do(func() {
			CloseConns(src, dst)
		})
	}

	stop := context.AfterFunc(ctx, closeOnce)

	defer func() {
		stop()
		closeOnce()
	}()

	bufPtr := bufferPool.Get().(*[]byte)
	defer bufferPool.Put(bufPtr)

	var n int64
	var err error
	if onFirst == nil {
		// Copy data from src to dst using the borrowed buffer.
		n, err = copyConns(dst, src, *bufPtr)
	} else {
		n, err = copyAfterFirstRead(dst, src, *bufPtr, onFirst)
	}

	// Filter benign errors.
	// os.IsTimeout is checked to handle UDP idle timeouts gracefully.
	if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) &&
		!errors.Is(err, syscall.EPIPE) && !os.IsTimeout(err) {
		resCh <- relayResult{Written: n, Dir: dir, Err: err}
		return
	}

	resCh <- relayResult{Written: n, Dir: dir, Err: nil}
}

// copyAfterFirstRead does the first read from src itself, so that onFirst
// sees it, then copies the rest like copyConns. The first read's bytes
// are in the count it returns. It returns what a read or write error of
// the first read would make io.CopyBuffer return.
func copyAfterFirstRead(
	dst io.Writer,
	src io.Reader,
	buf []byte,
	onFirst func(first []byte),
) (int64, error) {
	nr, rerr := src.Read(buf)
	var written int64
	if nr > 0 {
		onFirst(buf[:nr])
		nw, werr := dst.Write(buf[:nr])
		written = int64(nw)
		if werr == nil && nw < nr {
			werr = io.ErrShortWrite
		}
		if werr != nil {
			return written, werr
		}
	}
	if rerr != nil {
		if rerr == io.EOF {
			rerr = nil
		}
		return written, rerr
	}

	n, err := copyConns(dst, src, buf)
	return written + n, err
}

// copyConns copies from src to dst until EOF or an error. A BufferedConn src
// first gives the bytes its reader holds; then, like a BufferedConn dst, it
// is replaced by the conn it wraps.
//
// Between two *net.TCPConns, it leaves the copy to them: on Linux they
// splice in the kernel; on macOS and FreeBSD they allocate a buffer of
// their own for each direction. Any other pair copies with buf, and never
// through a ReadFrom or WriteTo of either conn, which could not splice and
// would allocate a buffer of its own.
func copyConns(dst io.Writer, src io.Reader, buf []byte) (int64, error) {
	var written int64
	if b, ok := src.(*BufferedConn); ok {
		n, err := b.writeBufferedTo(dst)
		written = int64(n)
		if err != nil {
			return written, err
		}
		src = b.Conn
	}
	if b, ok := dst.(*BufferedConn); ok {
		dst = b.Conn
	}

	_, srcIsTCP := src.(*net.TCPConn)
	_, dstIsTCP := dst.(*net.TCPConn)
	var n int64
	var err error
	if srcIsTCP && dstIsTCP {
		n, err = io.Copy(dst, src)
	} else {
		n, err = io.CopyBuffer(writerOnly{dst}, readerOnly{src}, buf)
	}
	return written + n, err
}

// readerOnly and writerOnly hide every method but Read and Write, so that
// io.CopyBuffer copies with its buffer instead of a ReadFrom or WriteTo.
type (
	readerOnly struct{ io.Reader }
	writerOnly struct{ io.Writer }
)

// RelayOptions are the optional hooks of RelayBidirectional.
type RelayOptions struct {
	// OnFirstReply receives the bytes of the first read from the remote,
	// before they are written to the client. It must not change or keep them.
	OnFirstReply func(first []byte)

	// HandleErrs turns the errors of the two directions into the error
	// RelayBidirectional returns. When nil, it returns the first error.
	HandleErrs func(errs []error) error
}

// RelayBidirectional copies between client and remote in both directions
// until either side ends, then waits for both directions, logs a summary at
// trace level and returns the error opts.HandleErrs makes of the directions'
// errors, or the first one. Each direction closes both conns when it ends,
// and so does the cancellation of ctx.
func RelayBidirectional(
	ctx context.Context,
	logger zerolog.Logger,
	client, remote net.Conn,
	opts RelayOptions,
) error {
	resCh := make(chan relayResult, 2)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	route := DescribeRoute(client, remote)

	startedAt := time.Now()
	go relayOneWay(ctx, resCh, client, remote, relayDirOut, nil)
	go relayOneWay(ctx, resCh, remote, client, relayDirIn, opts.OnFirstReply)

	var (
		outBytes int64
		inBytes  int64
		errs     []error
	)

	// Wait for exactly 2 results.
	for range 2 {
		res := <-resCh

		switch res.Dir {
		case relayDirOut:
			outBytes = res.Written
		case relayDirIn:
			inBytes = res.Written
		}

		if res.Err != nil {
			errs = append(errs, res.Err)
		}
	}

	duration := float64(time.Since(startedAt).Microseconds()) / 1000.0
	logger.Trace().
		Int64("out", outBytes).
		Int64("in", inBytes).
		Str("took", fmt.Sprintf("%.3fms", duration)).
		Str("route", route).
		Int("errs", len(errs)).
		Msg("tunnel closed")

	if opts.HandleErrs != nil {
		return opts.HandleErrs(errs)
	}

	if len(errs) > 0 {
		return errs[0]
	}

	return nil
}

func DescribeRoute(src, dst net.Conn) string {
	return fmt.Sprintf("%s(%s) -> %s(%s)",
		src.RemoteAddr(),
		src.RemoteAddr().Network(),
		dst.RemoteAddr(),
		dst.RemoteAddr().Network(),
	)
}

// CloseConns safely closes one or more io.Closer (like net.Conn).
// It is nil-safe and intentionally ignores errors from Close(),
// which is a common pattern in defer statements where handling the
// error is not feasible or desired.
func CloseConns(closers ...io.Closer) {
	for _, c := range closers {
		if c != nil {
			_ = c.Close()
		}
	}
}

// SetTTL configures the TTL or Hop Limit depending on the IP version.
// The isIPv4 parameter is determined by examining the remote address of the connection.
func SetTTL(conn net.Conn, isIPv4 bool, ttl uint8) error {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return errors.New("failed to cast to TCPConn")
	}

	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return err
	}

	// Re-check IP version using remote address to handle IPv4-mapped IPv6 addresses
	// On Linux, when using dual-stack sockets, the local address might be IPv6
	// but the actual connection could be IPv4-mapped (::ffff:x.x.x.x)
	actualIPv4 := isIPv4
	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		// If the IP is IPv4 or IPv4-mapped IPv6, we should use IPv4 options
		if ip4 := tcpAddr.IP.To4(); ip4 != nil {
			actualIPv4 = true
		}
	}

	var level, opt int
	if actualIPv4 {
		level = syscall.IPPROTO_IP
		opt = syscall.IP_TTL
	} else {
		level = syscall.IPPROTO_IPV6
		opt = syscall.IPV6_UNICAST_HOPS
	}

	var sysErr error

	// Invoke Control to manipulate file descriptor directly.
	err = rawConn.Control(func(fd uintptr) {
		sysErr = syscall.SetsockoptInt(int(fd), level, opt, int(ttl))
	})
	if err != nil {
		return err
	}

	return sysErr
}

// MSS returns the maximum segment size the kernel uses for conn: the
// largest TCP payload it puts in one packet.
func MSS(conn net.Conn) (int, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return 0, errors.New("failed to cast to TCPConn")
	}

	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return 0, err
	}

	var mss int
	var sysErr error
	err = rawConn.Control(func(fd uintptr) {
		mss, sysErr = syscall.GetsockoptInt(
			int(fd),
			syscall.IPPROTO_TCP,
			syscall.TCP_MAXSEG,
		)
	})
	if err != nil {
		return 0, err
	}

	return mss, sysErr
}

// BufferedConn wraps a net.Conn with a bufio.Reader to support peeking.
type BufferedConn struct {
	r *bufio.Reader
	net.Conn
}

func NewBufferedConn(c net.Conn) *BufferedConn {
	return &BufferedConn{
		r:    bufio.NewReader(c),
		Conn: c,
	}
}

func (b *BufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

func (b *BufferedConn) Peek(n int) ([]byte, error) {
	return b.r.Peek(n)
}

// writeBufferedTo writes the bytes that b's reader holds to w, and drops
// those that w took from the reader. It does not read from the conn, so
// after it returns without an error, the next byte of b is the next byte
// of the conn it wraps.
func (b *BufferedConn) writeBufferedTo(w io.Writer) (int, error) {
	buffered := b.r.Buffered()
	if buffered == 0 {
		return 0, nil
	}
	// Peek of no more than Buffered bytes neither reads nor fails.
	p, _ := b.r.Peek(buffered)
	n, err := w.Write(p)
	_, _ = b.r.Discard(n)
	if err == nil && n < buffered {
		err = io.ErrShortWrite
	}
	return n, err
}

// IdleTimeoutConn wraps a net.Conn to extend the deadline on every Read/Write call.
// This is useful for sessions which should stay alive as long as there is activity.
type IdleTimeoutConn struct {
	net.Conn

	timeout   int64 // time.Duration atomic
	expiredAt int64 // UnixNano atomic

	// deadlineMu serializes deadline updates, so an extension computed
	// with an old timeout can't overwrite the deadline SetTimeout set.
	deadlineMu sync.Mutex
}

// NewIdleTimeoutConn wraps a net.Conn and securely initializes its internal atomic deadlines.
func NewIdleTimeoutConn(conn net.Conn, timeout time.Duration) *IdleTimeoutConn {
	c := &IdleTimeoutConn{
		Conn:    conn,
		timeout: int64(timeout),
	}

	if timeout > 0 {
		c.setDeadline(time.Now().Add(timeout))
	}

	return c
}

func (c *IdleTimeoutConn) Read(b []byte) (int, error) {
	c.ExtendDeadline()
	return c.Conn.Read(b)
}

func (c *IdleTimeoutConn) Write(b []byte) (int, error) {
	c.ExtendDeadline()
	return c.Conn.Write(b)
}

// Timeout returns the idle timeout; 0 means the connection never expires.
func (c *IdleTimeoutConn) Timeout() time.Duration {
	return time.Duration(atomic.LoadInt64(&c.timeout))
}

// SetTimeout changes the idle timeout. When it changes, the idle period
// restarts with the new timeout, which later reads and writes extend; an
// already expired connection is left expired.
func (c *IdleTimeoutConn) SetTimeout(timeout time.Duration) {
	if c.Timeout() == timeout {
		// Unchanged: skip the lock and deadline syscalls on the hot path.
		return
	}

	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()

	now := time.Now()
	if c.IsExpired(now) {
		return
	}

	atomic.StoreInt64(&c.timeout, int64(timeout))
	if timeout > 0 {
		c.setDeadline(now.Add(timeout))
	} else {
		c.setDeadline(time.Time{})
	}
}

// ExtendDeadline attempts to extend the connection's deadline.
// Returns false if the connection was already expired.
func (c *IdleTimeoutConn) ExtendDeadline() bool {
	now := time.Now()
	nowUnix := now.UnixNano()

	// 1. Check if already expired (Thread-safe atomic read)
	expUnix := atomic.LoadInt64(&c.expiredAt)
	if expUnix != 0 && nowUnix > expUnix {
		return false
	}

	// 2. Throttle SetDeadline overhead (System Call)
	// Extends only if remaining time is under 70% of timeout
	timeout := c.Timeout()
	if timeout > 0 {
		if expUnix == 0 || (expUnix-nowUnix) < (timeout.Nanoseconds()*7/10) {
			c.deadlineMu.Lock()
			// SetTimeout may have changed the timeout since it was loaded.
			if timeout = c.Timeout(); timeout > 0 {
				c.setDeadline(now.Add(timeout))
			}
			c.deadlineMu.Unlock()
		}
	}

	return true
}

// setDeadline sets the expiry and the read and write deadlines to t; the
// zero t means no expiry.
func (c *IdleTimeoutConn) setDeadline(t time.Time) {
	var expUnix int64
	if !t.IsZero() {
		expUnix = t.UnixNano()
	}
	atomic.StoreInt64(&c.expiredAt, expUnix)
	_ = c.SetReadDeadline(t)
	_ = c.SetWriteDeadline(t)
}

// IsExpired safely checks if the connection has surpassed its calculated expiration time.
func (c *IdleTimeoutConn) IsExpired(now time.Time) bool {
	expUnix := atomic.LoadInt64(&c.expiredAt)
	return expUnix != 0 && now.UnixNano() > expUnix
}
