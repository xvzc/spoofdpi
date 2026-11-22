package server

import (
	"context"
	"time"

	"github.com/xvzc/spoofdpi/internal/logging"
)

// ShutdownSafetyTimeout bounds how long Serve waits for open connections to
// end after its context is cancelled.
const ShutdownSafetyTimeout = 10 * time.Second

// Server represents a core component that processes network traffic.
// Callers call Listen once and then Serve.
type Server interface {
	// Listen acquires what the server needs to accept traffic, such as the
	// listening socket or the TUN device and its network stack, and returns
	// without blocking. An error means the server cannot start.
	Listen(ctx context.Context) error

	// Serve handles traffic until ctx is cancelled. It then stops taking new
	// connections, waits at most ShutdownSafetyTimeout for open ones to end,
	// and releases what Listen acquired. It returns nil on a normal stop.
	Serve(ctx context.Context) error

	// Addr returns the network address or interface name the server is bound to
	Addr() string

	// SetupNetworkJobs builds the job list, saves it to the state file, and
	// returns the state file path. On darwin, HTTP/SOCKS5 also start the PAC
	// server, tied to ctx so it shuts down automatically when ctx is cancelled.
	// The returned path may be empty when the platform has nothing to configure.
	SetupNetworkJobs(ctx context.Context) (string, error)
}

const (
	backoffMin = 5 * time.Millisecond
	backoffMax = time.Second
)

// Backoff spaces out retries after consecutive errors, such as failed
// accepts. Each Wait sleeps twice as long as the one before, from 5ms up to
// 1s, until Reset starts over. The zero value is ready to use.
type Backoff struct {
	delay time.Duration
}

// Wait sleeps for the next delay, or until ctx is done.
func (b *Backoff) Wait(ctx context.Context) {
	timer := time.NewTimer(b.next())
	defer timer.Stop()

	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

// Reset makes the next Wait sleep for the shortest delay again. Callers
// call it after a success.
func (b *Backoff) Reset() {
	b.delay = 0
}

// next advances the delay and returns it.
func (b *Backoff) next() time.Duration {
	b.delay = min(max(b.delay*2, backoffMin), backoffMax)
	return b.delay
}

// ConnContext returns the context of one connection. It starts from a fresh
// root so the connection gets its own trace ID, and it is cancelled when
// parent (the server's context) ends. The caller must call the returned
// cancel when the connection is done.
func ConnContext(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	stop := context.AfterFunc(parent, cancel)

	return logging.ContextWithTraceID(ctx, logging.NewTraceID()), func() {
		stop()
		cancel()
	}
}
