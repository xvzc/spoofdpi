package netutil

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
)

// scriptedConn returns the queued errors from Read and Write in order,
// then succeeds.
type scriptedConn struct {
	net.Conn
	errs  []error
	calls int
}

func (c *scriptedConn) next(b []byte) (int, error) {
	c.calls++
	if len(c.errs) > 0 {
		err := c.errs[0]
		c.errs = c.errs[1:]
		return 0, err
	}
	return len(b), nil
}

func (c *scriptedConn) Read(b []byte) (int, error)  { return c.next(b) }
func (c *scriptedConn) Write(b []byte) (int, error) { return c.next(b) }

func opErr(errno syscall.Errno) error {
	return &net.OpError{Op: "read", Net: "udp", Err: fmt.Errorf("wrapped: %w", errno)}
}

func TestIsICMPError(t *testing.T) {
	assert.True(t, isICMPError(opErr(syscall.ECONNREFUSED)))
	assert.True(t, isICMPError(opErr(syscall.EHOSTUNREACH)))
	assert.True(t, isICMPError(opErr(syscall.ENETUNREACH)))
	assert.False(t, isICMPError(opErr(syscall.ECONNRESET)))
	assert.False(t, isICMPError(net.ErrClosed))
	assert.False(t, isICMPError(nil))
}

func TestICMPTolerantConn(t *testing.T) {
	for _, op := range []string{"read", "write"} {
		call := func(c net.Conn) (int, error) {
			if op == "read" {
				return c.Read(make([]byte, 4))
			}
			return c.Write(make([]byte, 4))
		}

		t.Run(op+" skips icmp errors", func(t *testing.T) {
			inner := &scriptedConn{errs: []error{
				opErr(syscall.EHOSTUNREACH),
				opErr(syscall.ECONNREFUSED),
			}}
			n, err := call(NewICMPTolerantConn(inner))
			assert.NoError(t, err)
			assert.Equal(t, 4, n)
			assert.Equal(t, 3, inner.calls)
		})

		t.Run(op+" returns other errors", func(t *testing.T) {
			want := opErr(syscall.ECONNRESET)
			inner := &scriptedConn{errs: []error{want}}
			_, err := call(NewICMPTolerantConn(inner))
			assert.True(t, errors.Is(err, syscall.ECONNRESET))
			assert.Equal(t, 1, inner.calls)
		})

		t.Run(op+" gives up after too many icmp errors", func(t *testing.T) {
			errs := make([]error, maxICMPErrors+5)
			for i := range errs {
				errs[i] = opErr(syscall.EHOSTUNREACH)
			}
			inner := &scriptedConn{errs: errs}
			_, err := call(NewICMPTolerantConn(inner))
			assert.True(t, errors.Is(err, syscall.EHOSTUNREACH))
			assert.Equal(t, maxICMPErrors+1, inner.calls)
		})
	}
}
