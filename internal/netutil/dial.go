package netutil

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
)

type dialResult struct {
	conn net.Conn
	err  error
}

// BindFunc is called to configure the dialer before dialing.
// If it returns an error, the dial attempt fails.
type BindFunc func(dialer *net.Dialer, network string, targetIP net.IP) error

// dialContext dials addr with d. Tests replace it to fake the network.
var dialContext = func(
	ctx context.Context,
	d *net.Dialer,
	network, addr string,
) (net.Conn, error) {
	return d.DialContext(ctx, network, addr)
}

// DialFastest attempts robust connections to the server
// and returns the first successful conn. All the other connections will be
// automatically canceled by calling `cancel()`, and every one of them that
// was established is closed.
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

	// Each attempt sends exactly one result, so sends never block. The
	// channel is closed once every launched attempt has sent its result.
	results := make(chan dialResult, len(dst.Addrs))
	// Closes the conns DialFastest does not return, including those that
	// arrive after it has returned.
	defer func() {
		go func() {
			for res := range results {
				if res.conn != nil {
					_ = res.conn.Close()
				}
			}
		}()
	}()

	const maxConcurrency = 10
	sem := make(chan struct{}, maxConcurrency) // semaphore

	var attempts sync.WaitGroup
	attempts.Add(1) // the launcher, so results stays open while it runs
	go func() {
		attempts.Wait()
		close(results)
	}()

	go func() {
		defer attempts.Done()
		for _, addr := range dst.Addrs {
			// Get semaphore
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}

			attempts.Add(1)
			go func(ip net.IP) {
				defer attempts.Done()
				defer func() { <-sem }() // Return semaphore

				targetAddr := net.JoinHostPort(ip.String(), strconv.Itoa(dst.Port))
				dialer := &net.Dialer{}
				if timeout > 0 {
					dialer.Deadline = time.Now().Add(timeout)
				}

				// Apply bind function if provided
				if bindFunc != nil {
					if err := bindFunc(dialer, network, ip); err != nil {
						results <- dialResult{conn: nil, err: err}
						return
					}
				}

				conn, err := dialContext(ctx, dialer, network, targetAddr)
				if err == nil && ctx.Err() != nil {
					// DialFastest has returned or is returning without
					// this conn.
					_ = conn.Close()
					conn, err = nil, ctx.Err()
				}
				results <- dialResult{conn: conn, err: err}
			}(addr)
		}
	}()

	var firstError error
	failureCount := 0

	for {
		select {
		case res, ok := <-results:
			if !ok {
				// Every attempt has failed, or the launcher stopped
				// early because ctx is done.
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				return nil, fmt.Errorf(
					"all connection attempts failed (total %d): %w",
					failureCount,
					firstError,
				)
			}
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
}
