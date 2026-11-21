package probe

import (
	"context"
	"sync"
	"time"
)

// defaultStagger is the delay between the starts of two attempts of a scan
// round, so that a round does not send a burst of packets.
const defaultStagger = 5 * time.Millisecond

// reachFunc makes one attempt to reach the server with the given TTL and
// reports whether it did. localErr is set when the attempt failed on this
// host, such as for lack of file descriptors, which says nothing about the
// path.
type reachFunc func(ctx context.Context, ttl int) (reached bool, localErr error)

// scanResult is the outcome of a TTL scan.
type scanResult struct {
	// minTTL is the smallest TTL that reached the server, or 0 if none did.
	minTTL int
	// unstable is set when some TTL above minTTL never reached the server
	// in an attempt that did not fail locally.
	unstable bool
	// localErr is the first local error of an attempt, if any.
	localErr error
}

// scan finds the smallest TTL in 1..maxTTL that reaches the server. The
// first round tries every TTL at once, starting one attempt every stagger.
// Each of the other rounds, up to rounds in all, retries every TTL that
// has not reached it yet: those below the smallest one that did, so that a
// lost packet at the threshold does not raise the result, and those above
// it, so that a lost packet is not taken for an unstable path. It stops
// early when every TTL reached. A linear or binary search would be slower,
// since a TTL that does not reach often costs a full timeout, and loss or
// a path that changes between connections would mislead a binary search.
func scan(
	ctx context.Context,
	maxTTL, rounds int,
	stagger time.Duration,
	reaches reachFunc,
) scanResult {
	reached := make([]bool, maxTTL+1)
	// tried is set for a TTL with an attempt that did not fail locally:
	// only such a TTL tells that the path varies when it never reaches.
	tried := make([]bool, maxTTL+1)
	var localErr error
	pending := make([]int, 0, maxTTL)
	for ttl := 1; ttl <= maxTTL; ttl++ {
		pending = append(pending, ttl)
	}
	for round := 0; round < rounds && len(pending) > 0 && ctx.Err() == nil; round++ {
		res := scanRound(ctx, pending, stagger, reaches)
		for _, ttl := range res.reached {
			reached[ttl] = true
		}
		for _, ttl := range res.tried {
			tried[ttl] = true
		}
		if localErr == nil {
			localErr = res.localErr
		}
		pending = pending[:0]
		for ttl := 1; ttl <= maxTTL; ttl++ {
			if !reached[ttl] {
				pending = append(pending, ttl)
			}
		}
	}

	res := scanResult{localErr: localErr}
	for ttl := 1; ttl <= maxTTL; ttl++ {
		switch {
		case res.minTTL == 0 && reached[ttl]:
			res.minTTL = ttl
		case res.minTTL != 0 && !reached[ttl] && tried[ttl]:
			res.unstable = true
		}
	}
	return res
}

// roundResult is the outcome of a scan round.
type roundResult struct {
	// reached are the TTLs that reached the server, and tried those whose
	// attempt did not fail locally.
	reached, tried []int
	// localErr is the first local error of an attempt, if any.
	localErr error
}

// scanRound tries every TTL in ttls concurrently.
func scanRound(
	ctx context.Context,
	ttls []int,
	stagger time.Duration,
	reaches reachFunc,
) roundResult {
	var (
		mu  sync.Mutex
		res roundResult
		wg  sync.WaitGroup
	)
	for i, ttl := range ttls {
		if i > 0 && !sleep(ctx, stagger) {
			break
		}
		wg.Go(func() {
			ok, localErr := reaches(ctx, ttl)
			mu.Lock()
			defer mu.Unlock()
			if ok {
				res.reached = append(res.reached, ttl)
			}
			if localErr == nil {
				res.tried = append(res.tried, ttl)
			}
			if res.localErr == nil {
				res.localErr = localErr
			}
		})
	}
	wg.Wait()
	return res
}

// sleep waits for d and reports whether ctx is still not done.
func sleep(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}
