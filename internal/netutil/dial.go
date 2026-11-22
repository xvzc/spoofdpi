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

// defaultAttemptDelay is the delay between connection attempts that RFC 8305,
// section 8, recommends.
const defaultAttemptDelay = 250 * time.Millisecond

// DialOptions configures the attempts of DialFastest.
type DialOptions struct {
	// Timeout is applied to each attempt as a deadline, from the start of
	// that attempt; 0 disables it. As attempts start AttemptDelay apart,
	// dialing k addresses can take up to (k-1)*AttemptDelay + Timeout.
	Timeout time.Duration
	// Bind, if not nil, configures the dialer before each attempt.
	Bind BindFunc
	// AttemptDelay is how long DialFastest waits for an attempt before it
	// starts the next one; 0 means 250ms.
	AttemptDelay time.Duration
}

// DialFastest connects to dst with Happy Eyeballs (RFC 8305) and returns
// the first successful conn. It tries the addresses of dst alternating
// between IPv4 and IPv6, starting with the family of the first address and
// keeping their order within each family. Each attempt starts
// o.AttemptDelay after the previous one, or as soon as an attempt fails.
// Once a conn is returned, the other attempts are cancelled, and every one
// of them that was established is closed.
func DialFastest(
	ctx context.Context,
	dst *Destination,
	network string,
	o DialOptions,
) (net.Conn, error) {
	if len(dst.Addrs) == 0 {
		return nil, fmt.Errorf("no addresses provided to dial")
	}

	attemptDelay := o.AttemptDelay
	if attemptDelay == 0 {
		attemptDelay = defaultAttemptDelay
	}
	addrs := interleaveFamilies(dst.Addrs)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Each attempt sends exactly one result, so sends never block. The
	// channel is closed once every launched attempt has sent its result.
	results := make(chan dialResult, len(addrs))
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
	// Each failed attempt sends one token, which starts the next attempt
	// without waiting for attemptDelay. Sends never block.
	failed := make(chan struct{}, len(addrs))

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
		for i, addr := range addrs {
			if i > 0 && !waitNextAttempt(ctx, attemptDelay, failed) {
				return
			}

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

				res := dialAttempt(ctx, dst, ip, network, o)
				if res.err != nil {
					failed <- struct{}{}
				}
				results <- res
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

// dialAttempt dials ip, one of the addresses of dst, on the port of dst, and
// with its zone when ip is link-local. It closes a conn established after
// ctx is done, as DialFastest has returned or is returning without it.
func dialAttempt(
	ctx context.Context,
	dst *Destination,
	ip net.IP,
	network string,
	o DialOptions,
) dialResult {
	host := ip.String()
	if dst.Zone != "" && NeedsZone(ip) {
		host += "%" + dst.Zone
	}
	targetAddr := net.JoinHostPort(host, strconv.Itoa(dst.Port))
	dialer := &net.Dialer{}
	if o.Timeout > 0 {
		dialer.Deadline = time.Now().Add(o.Timeout)
	}

	if o.Bind != nil {
		if err := o.Bind(dialer, network, ip); err != nil {
			return dialResult{err: err}
		}
	}

	conn, err := dialContext(ctx, dialer, network, targetAddr)
	if err == nil && ctx.Err() != nil {
		_ = conn.Close()
		conn, err = nil, ctx.Err()
	}
	return dialResult{conn: conn, err: err}
}

// waitNextAttempt waits until the next attempt may start: after delay, or
// at once when an attempt has failed. It reports false when ctx is done
// first.
func waitNextAttempt(
	ctx context.Context,
	delay time.Duration,
	failed <-chan struct{},
) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-timer.C:
		return true
	case <-failed:
		return true
	case <-ctx.Done():
		return false
	}
}

// interleaveFamilies orders addrs as RFC 8305, section 4, does with a
// "First Address Family Count" of 1: it alternates between IPv4 and IPv6,
// starting with the family of addrs[0], and keeps the order of addrs within
// each family. An IPv4-mapped IPv6 address counts as IPv4.
func interleaveFamilies(addrs []net.IP) []net.IP {
	firstIs4 := addrs[0].To4() != nil
	var first, second []net.IP
	for _, ip := range addrs {
		if (ip.To4() != nil) == firstIs4 {
			first = append(first, ip)
		} else {
			second = append(second, ip)
		}
	}

	ordered := make([]net.IP, 0, len(addrs))
	for i := 0; i < len(first) || i < len(second); i++ {
		if i < len(first) {
			ordered = append(ordered, first[i])
		}
		if i < len(second) {
			ordered = append(ordered, second[i])
		}
	}
	return ordered
}
