package server

import (
	"context"
	"time"
)

// Server represents a core component that processes network traffic.
// ListenAndServe blocks until ctx is cancelled, then releases all resources.
type Server interface {
	ListenAndServe(ctx context.Context) error

	// Addr returns the network address or interface name the server is bound to
	Addr() string

	// SetupNetworkJobs builds the job list, saves it to the state file, and
	// returns the state file path. For HTTP/SOCKS5 this also starts the PAC
	// server, tied to ctx so it shuts down automatically when ctx is cancelled.
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
