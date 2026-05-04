package netutil

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"
)

type dialResult struct {
	conn net.Conn
	err  error
}

// BindFunc is called to configure the dialer before dialing.
// If it returns an error, the dial attempt fails.
type BindFunc func(dialer *net.Dialer, network string, targetIP net.IP) error

// DialFastest attempts robust connections to the server
// and returns the first successful conn. All the other connections will be
// automatically canceled by calling `cancel()`
// timeout is applied per-dial as a deadline; pass 0 to disable.
// If bindFunc is not nil, it is called to configure the dialer before each dial attempt.
func DialFastest(
	ctx context.Context,
	dst *Destination,
	network string,
	timeout time.Duration,
	bindFunc BindFunc,
) (net.Conn, error) {
	if len(dst.Addrs) == 0 {
		return nil, fmt.Errorf("no addresses provided to dial")
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan dialResult, len(dst.Addrs))

	const maxConcurrency = 10
	sem := make(chan struct{}, maxConcurrency) // semaphore

	go func() {
		for _, addr := range dst.Addrs {
			// Get semaphore
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}

			go func(ip net.IP) {
				defer func() { <-sem }() // Return semaphore

				targetAddr := net.JoinHostPort(ip.String(), strconv.Itoa(dst.Port))
				dialer := &net.Dialer{}
				if timeout > 0 {
					dialer.Deadline = time.Now().Add(timeout)
				}

				// Apply bind function if provided
				if bindFunc != nil {
					if err := bindFunc(dialer, network, ip); err != nil {
						select {
						case results <- dialResult{conn: nil, err: err}:
						case <-ctx.Done():
						}
						return
					}
				}

				conn, err := dialer.DialContext(ctx, network, targetAddr)

				select {
				case results <- dialResult{conn: conn, err: err}:
				case <-ctx.Done():
					if conn != nil {
						_ = conn.Close() // Close on context cancel
					}
				}
			}(addr)
		}
	}()

	var firstError error
	failureCount := 0

	for range dst.Addrs {
		select {
		case res := <-results:
			if res.err == nil {
				return &TrackingConn{Conn: res.conn}, nil
			}
			if firstError == nil {
				firstError = res.err
			}
			failureCount++
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	return nil, fmt.Errorf(
		"all connection attempts failed (total %d): %w",
		failureCount,
		firstError,
	)
}
