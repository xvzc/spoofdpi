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

var (
	txBytes uint64
	rxBytes uint64
)

type TunnelDirType int

const (
	TunnelDirOut TunnelDirType = iota
	TunnelDirIn
)

// TransferResult holds the result of a unidirectional tunnel transfer.
type TransferResult struct {
	Written int64
	Dir     TunnelDirType
	Err     error
}

// bufferPool is a package-level pool of 32KB buffers used by io.CopyBuffer
// to reduce memory allocations and GC pressure in the tunnel hot path.
var bufferPool = sync.Pool{
	New: func() any {
		// We allocate a pointer to a byte slice.
		// 32KB is the default buffer size for io.Copy.
		b := make([]byte, 32*1024)
		return &b
	},
}

// TunnelConns copies data from src to dst.
// It sends the result to resCh upon completion.
// It filters out benign errors like EOF, pipe closed, or read timeouts (for UDP).
func TunnelConns(
	ctx context.Context,
	resCh chan<- TransferResult,
	src net.Conn, // Source connection (io.Reader)
	dst net.Conn, // Destination connection (io.Writer)
	dir TunnelDirType,
) {
	TunnelConnsFirstRead(ctx, resCh, src, dst, dir, nil)
}

// TunnelConnsFirstRead is TunnelConns that hands the bytes of the first read
// from src to onFirst, before it writes them to dst. onFirst must not
// change or keep them. It copies the rest with src itself, not a wrapper of
// it, so that a TCP src and dst keep the kernel splice. With a nil onFirst
// it is TunnelConns.
func TunnelConnsFirstRead(
	ctx context.Context,
	resCh chan<- TransferResult,
	src net.Conn,
	dst net.Conn,
	dir TunnelDirType,
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
		n, err = io.CopyBuffer(dst, src, *bufPtr)
	} else {
		n, err = copyAfterFirstRead(dst, src, *bufPtr, onFirst)
	}

	// Filter benign errors.
	// os.IsTimeout is checked to handle UDP idle timeouts gracefully.
	if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) &&
		!errors.Is(err, syscall.EPIPE) && !os.IsTimeout(err) {
		resCh <- TransferResult{Written: n, Dir: dir, Err: err}
		return
	}

	resCh <- TransferResult{Written: n, Dir: dir, Err: nil}
}

// copyAfterFirstRead does the first read from src itself, so that onFirst
// sees it, then copies the rest like io.CopyBuffer. The first read's bytes
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

	n, err := io.CopyBuffer(dst, src, buf)
	return written + n, err
}

// WaitForTunnelCompletion aggregates results and logs the summary.
// errHandler processes the list of errors to determine the final error.
func WaitForTunnelCompletion(
	ctx context.Context,
	logger zerolog.Logger,
	resCh <-chan TransferResult,
	startedAt time.Time,
	route string,
	errHandler func(errs []error) error, // [Modified] Accepts slice handler
) error {
	var (
		outBytes int64
		inBytes  int64
		errs     []error // Collect all errors
	)

	// Wait for exactly 2 results.
	for range 2 {
		res := <-resCh

		switch res.Dir {
		case TunnelDirOut:
			outBytes = res.Written
		case TunnelDirIn:
			inBytes = res.Written
		default:
			return fmt.Errorf("invalid tunnel dir")
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

	if errHandler != nil {
		return errHandler(errs)
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
	if tc, ok := conn.(*TrackingConn); ok {
		conn = tc.Conn
	}
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
	if tc, ok := conn.(*TrackingConn); ok {
		conn = tc.Conn
	}
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

type TrackingConn struct {
	net.Conn
}

func (c *TrackingConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if n > 0 {
		atomic.AddUint64(&rxBytes, uint64(n))
	}
	return
}

func (c *TrackingConn) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)
	if n > 0 {
		atomic.AddUint64(&txBytes, uint64(n))
	}
	return
}

func GetRxBytes() uint64 {
	return atomic.LoadUint64(&rxBytes)
}

func GetTxBytes() uint64 {
	return atomic.LoadUint64(&txBytes)
}
