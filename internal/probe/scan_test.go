package probe

import (
	"context"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// attempts records the attempts of a scan by TTL.
type attempts struct {
	mu    sync.Mutex
	calls map[int]int
}

// reach returns a reachFunc that records each attempt and reaches when
// ok returns true for the TTL and the attempt number (1 for the first).
func (a *attempts) reach(ok func(ttl, n int) bool) reachFunc {
	a.calls = map[int]int{}
	return func(ctx context.Context, ttl int) (bool, error) {
		a.mu.Lock()
		a.calls[ttl]++
		n := a.calls[ttl]
		a.mu.Unlock()
		return ok(ttl, n), nil
	}
}

func TestScan(t *testing.T) {
	tcs := []struct {
		name         string
		maxTTL       int
		rounds       int
		ok           func(ttl, n int) bool
		wantMin      int
		wantUnstable bool
		wantCalls    map[int]int
	}{
		{
			name:   "threshold",
			maxTTL: 6, rounds: 2,
			ok:        func(ttl, n int) bool { return ttl >= 4 },
			wantMin:   4,
			wantCalls: map[int]int{1: 2, 2: 2, 3: 2, 4: 1, 5: 1, 6: 1},
		},
		{
			name:   "loss at the threshold is retried",
			maxTTL: 6, rounds: 2,
			ok:        func(ttl, n int) bool { return ttl >= 5 || (ttl == 4 && n > 1) },
			wantMin:   4,
			wantCalls: map[int]int{1: 2, 2: 2, 3: 2, 4: 2, 5: 1, 6: 1},
		},
		{
			name:   "loss at the threshold with one round",
			maxTTL: 6, rounds: 1,
			ok:      func(ttl, n int) bool { return ttl >= 5 || (ttl == 4 && n > 1) },
			wantMin: 5,
		},
		{
			name:   "loss above the threshold is retried",
			maxTTL: 6, rounds: 2,
			ok:      func(ttl, n int) bool { return ttl >= 4 && (ttl != 5 || n > 1) },
			wantMin: 4,
		},
		{
			name:   "a higher TTL that never reaches is unstable",
			maxTTL: 6, rounds: 3,
			ok:           func(ttl, n int) bool { return ttl >= 3 && ttl != 5 },
			wantMin:      3,
			wantUnstable: true,
			wantCalls:    map[int]int{1: 3, 2: 3, 3: 1, 4: 1, 5: 3, 6: 1},
		},
		{
			name:   "nothing reaches",
			maxTTL: 4, rounds: 2,
			ok:        func(ttl, n int) bool { return false },
			wantMin:   0,
			wantCalls: map[int]int{1: 2, 2: 2, 3: 2, 4: 2},
		},
		{
			name:   "stops early when every TTL reached",
			maxTTL: 4, rounds: hopTries,
			ok:        func(ttl, n int) bool { return true },
			wantMin:   1,
			wantCalls: map[int]int{1: 1, 2: 1, 3: 1, 4: 1},
		},
		{
			name:   "stops once the TTLs left reach",
			maxTTL: 4, rounds: hopTries,
			ok:        func(ttl, n int) bool { return n > 1 },
			wantMin:   1,
			wantCalls: map[int]int{1: 2, 2: 2, 3: 2, 4: 2},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			var a attempts
			got := scan(context.Background(), tc.maxTTL, tc.rounds, 0, a.reach(tc.ok))
			assert.Equal(t, scanResult{minTTL: tc.wantMin, unstable: tc.wantUnstable}, got)
			if tc.wantCalls != nil {
				assert.Equal(t, tc.wantCalls, a.calls)
			}
		})
	}
}

func TestScan_RoundRunsConcurrently(t *testing.T) {
	const maxTTL = 8
	var started sync.WaitGroup
	started.Add(maxTTL)
	allStarted := make(chan struct{})
	go func() { started.Wait(); close(allStarted) }()

	got := scan(context.Background(), maxTTL, 1, time.Millisecond,
		func(ctx context.Context, ttl int) (bool, error) {
			started.Done()
			select {
			case <-allStarted:
				return true, nil
			case <-time.After(5 * time.Second):
				return false, nil
			}
		})
	assert.Equal(t, 1, got.minTTL, "every attempt ran while the others waited")
}

func TestScan_Cancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var a attempts
	reach := a.reach(func(ttl, n int) bool { return false })

	start := time.Now()
	got := scan(
		ctx,
		32,
		5,
		10*time.Millisecond,
		func(ctx context.Context, ttl int) (bool, error) {
			if ttl == 3 {
				cancel()
			}
			<-ctx.Done()
			return reach(ctx, ttl)
		},
	)
	assert.Less(t, time.Since(start), 2*time.Second)
	assert.Equal(t, scanResult{}, got)
	assert.Equal(
		t,
		map[int]int{1: 1, 2: 1, 3: 1},
		a.calls,
		"no attempt starts after the cancel",
	)
}

func TestScan_LocalError(t *testing.T) {
	var calls sync.Map
	got := scan(
		context.Background(),
		6,
		2,
		0,
		func(ctx context.Context, ttl int) (bool, error) {
			n, _ := calls.LoadOrStore(ttl, new(int))
			*n.(*int)++
			// TTL 3, the threshold, fails locally in the first round only.
			if ttl == 3 && *n.(*int) == 1 {
				return false, syscall.EMFILE
			}
			return ttl >= 3, nil
		},
	)
	assert.Equal(t, scanResult{minTTL: 3, localErr: syscall.EMFILE}, got,
		"the local error is kept, and its TTL retried")
}

func TestScan_LocalErrorIsNotUnstable(t *testing.T) {
	got := scan(
		context.Background(),
		6,
		3,
		0,
		func(ctx context.Context, ttl int) (bool, error) {
			// TTL 5, above the threshold, only ever fails locally.
			if ttl == 5 {
				return false, syscall.EMFILE
			}
			return ttl >= 3, nil
		},
	)
	assert.Equal(t, scanResult{minTTL: 3, localErr: syscall.EMFILE}, got,
		"a TTL that only failed locally says nothing about the path")
}
