package server

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ConnTracker runs one goroutine per accepted connection and lets the server
// wait for all of them at shutdown. The zero value is ready to use.
type ConnTracker struct {
	mu      sync.Mutex
	closing bool
	wg      sync.WaitGroup
	active  atomic.Int64
}

// Go handles conn with fn in a tracked goroutine. fn gets the connection's
// context from ConnContext(parent); when that context is cancelled, conn is
// closed at once, so a handler blocked reading from it returns. A connection
// passed to Go after Wait has started is closed without running fn, because
// the server is already shutting down.
func (t *ConnTracker) Go(
	parent context.Context,
	conn net.Conn,
	fn func(ctx context.Context),
) {
	t.mu.Lock()
	if t.closing {
		t.mu.Unlock()
		_ = conn.Close()
		return
	}
	t.wg.Add(1)
	t.mu.Unlock()

	t.active.Add(1)
	ctx, cancel := ConnContext(parent)
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })

	go func() {
		defer t.wg.Done()
		defer t.active.Add(-1)
		defer func() {
			stop()
			cancel()
		}()

		fn(ctx)
	}()
}

// Wait waits up to timeout for every goroutine started by Go to return, and
// reports whether they all did. Once Wait is called, Go starts no new
// goroutines.
func (t *ConnTracker) Wait(timeout time.Duration) bool {
	t.mu.Lock()
	t.closing = true
	t.mu.Unlock()

	done := make(chan struct{})
	go func() {
		t.wg.Wait()
		close(done)
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	}
}

// Active returns the number of goroutines started by Go that have not
// returned yet.
func (t *ConnTracker) Active() int64 {
	return t.active.Load()
}
