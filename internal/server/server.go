package server

import (
	"context"
	"time"

	"github.com/xvzc/spoofdpi/internal/logging"
)

// Server represents a core component that processes network traffic.
// ListenAndServe blocks until ctx is cancelled, then releases all resources.
type Server interface {
	ListenAndServe(ctx context.Context) error

	// Addr returns the network address or interface name the server is bound to
	Addr() string

	// SetupNetworkJobs builds the job list, saves it to the state file, and
	// returns the state file path. On darwin, HTTP/SOCKS5 also start the PAC
	// server, tied to ctx so it shuts down automatically when ctx is cancelled.
	// The returned path may be empty when the platform has nothing to configure.
	SetupNetworkJobs(ctx context.Context) (string, error)
}

func BackoffOnError(delay time.Duration) time.Duration {
	if delay == 0 {
		delay = 5
	} else {
		delay *= 2
	}
	if max := 10 * time.Second; delay > max {
		delay = max
	}

	time.Sleep(delay)

	return delay
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
