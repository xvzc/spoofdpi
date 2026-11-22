package netutil

import (
	"context"
	"errors"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeConn is a conn that records whether it was closed.
type fakeConn struct {
	net.Conn
	addr   string
	closed atomic.Bool
}

func (c *fakeConn) Close() error {
	c.closed.Store(true)
	return nil
}

// fakeDialer replaces dialContext for one test. dial decides the outcome
// of each attempt; every conn it hands out is recorded.
type fakeDialer struct {
	mu    sync.Mutex
	conns []*fakeConn
	calls sync.WaitGroup
}

func newFakeDialer(
	t *testing.T,
	dial func(ctx context.Context, addr string) error,
) *fakeDialer {
	t.Helper()

	f := &fakeDialer{}
	orig := dialContext
	dialContext = func(
		ctx context.Context,
		_ *net.Dialer,
		_, addr string,
	) (net.Conn, error) {
		f.calls.Add(1)
		defer f.calls.Done()

		if err := dial(ctx, addr); err != nil {
			return nil, err
		}
		c := &fakeConn{addr: addr}
		f.mu.Lock()
		f.conns = append(f.conns, c)
		f.mu.Unlock()
		return c, nil
	}
	t.Cleanup(func() { dialContext = orig })
	return f
}

// requireLosersClosed waits for every dial to return, then requires every
// conn other than winner to be closed within a second, winner to stay
// open, and no goroutine started by DialFastest to remain.
func (f *fakeDialer) requireLosersClosed(
	t *testing.T,
	winner net.Conn,
	goroutinesBefore int,
) {
	t.Helper()

	f.calls.Wait()
	var won *fakeConn
	if winner != nil {
		won = winner.(*TrackingConn).Conn.(*fakeConn)
	}

	require.Eventually(t, func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, c := range f.conns {
			if c != won && !c.closed.Load() {
				return false
			}
		}
		return true
	}, time.Second, time.Millisecond, "a losing conn was not closed")

	if won != nil {
		assert.False(t, won.closed.Load(), "the returned conn was closed")
	}
	// Polled here, not with require.Eventually, whose own goroutines
	// would be counted.
	for deadline := time.Now().Add(time.Second); ; time.Sleep(time.Millisecond) {
		if runtime.NumGoroutine() <= goroutinesBefore {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf(
				"DialFastest left goroutines behind: %d, want at most %d",
				runtime.NumGoroutine(),
				goroutinesBefore,
			)
		}
	}
}

func testDestination(ips ...string) *Destination {
	d := &Destination{Host: "example.com", Port: 443}
	for _, ip := range ips {
		d.Addrs = append(d.Addrs, net.ParseIP(ip))
	}
	return d
}

func TestDialFastest_TwoSimultaneousSuccesses(t *testing.T) {
	before := runtime.NumGoroutine()

	var entered sync.WaitGroup
	entered.Add(2)
	f := newFakeDialer(t, func(context.Context, string) error {
		// Both attempts succeed together, after both have started.
		entered.Done()
		entered.Wait()
		return nil
	})

	conn, err := DialFastest(
		context.Background(),
		testDestination("192.0.2.1", "192.0.2.2"),
		"tcp",
		0,
		nil,
	)
	require.NoError(t, err)
	f.requireLosersClosed(t, conn, before)
	assert.Len(t, f.conns, 2)
}

func TestDialFastest_SuccessAfterCancel(t *testing.T) {
	before := runtime.NumGoroutine()

	lateEntered := make(chan struct{})
	f := newFakeDialer(t, func(ctx context.Context, addr string) error {
		if addr == "192.0.2.2:443" {
			// A dial that completes although its ctx was cancelled.
			close(lateEntered)
			<-ctx.Done()
			return nil
		}
		<-lateEntered
		return nil
	})

	conn, err := DialFastest(
		context.Background(),
		testDestination("192.0.2.1", "192.0.2.2"),
		"tcp",
		0,
		nil,
	)
	require.NoError(t, err)
	assert.Equal(t, "192.0.2.1:443", conn.(*TrackingConn).Conn.(*fakeConn).addr)
	f.requireLosersClosed(t, conn, before)
	assert.Len(t, f.conns, 2)
}

func TestDialFastest_ParentCancelledWhileDialing(t *testing.T) {
	before := runtime.NumGoroutine()

	ctx, cancel := context.WithCancel(context.Background())
	var entered sync.WaitGroup
	entered.Add(2)
	release := make(chan struct{})
	f := newFakeDialer(t, func(context.Context, string) error {
		entered.Done()
		<-release
		return nil
	})

	errc := make(chan error, 1)
	go func() {
		conn, err := DialFastest(
			ctx,
			testDestination("192.0.2.1", "192.0.2.2"),
			"tcp",
			0,
			nil,
		)
		assert.Nil(t, conn)
		errc <- err
	}()

	entered.Wait()
	cancel()
	require.ErrorIs(t, <-errc, context.Canceled)

	// The dials complete only after DialFastest has returned.
	close(release)
	f.requireLosersClosed(t, nil, before)
	assert.Len(t, f.conns, 2)
}

func TestDialFastest_AllAttemptsFail(t *testing.T) {
	before := runtime.NumGoroutine()

	refused := errors.New("connection refused")
	f := newFakeDialer(t, func(context.Context, string) error { return refused })

	conn, err := DialFastest(
		context.Background(),
		testDestination("192.0.2.1", "192.0.2.2", "192.0.2.3"),
		"tcp",
		0,
		nil,
	)
	require.ErrorIs(t, err, refused)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "total 3")
	f.requireLosersClosed(t, nil, before)
}

func TestDialFastest_BindFailure(t *testing.T) {
	before := runtime.NumGoroutine()

	bindErr := errors.New("bind failed")
	f := newFakeDialer(t, func(context.Context, string) error { return nil })

	conn, err := DialFastest(
		context.Background(),
		testDestination("192.0.2.1"),
		"tcp",
		0,
		func(*net.Dialer, string, net.IP) error { return bindErr },
	)
	require.ErrorIs(t, err, bindErr)
	assert.Nil(t, conn)
	f.requireLosersClosed(t, nil, before)
	assert.Empty(t, f.conns)
}

func TestDialFastest_OneAddress(t *testing.T) {
	before := runtime.NumGoroutine()

	f := newFakeDialer(t, func(context.Context, string) error { return nil })

	conn, err := DialFastest(
		context.Background(),
		testDestination("2001:db8::1"),
		"tcp",
		0,
		nil,
	)
	require.NoError(t, err)
	assert.Equal(t, "[2001:db8::1]:443", conn.(*TrackingConn).Conn.(*fakeConn).addr)
	f.requireLosersClosed(t, conn, before)
}

func TestDialFastest_NoAddresses(t *testing.T) {
	_, err := DialFastest(context.Background(), testDestination(), "tcp", 0, nil)
	require.Error(t, err)
}
