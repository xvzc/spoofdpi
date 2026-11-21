package probe

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeDPI answers the attempts of the DPI checks as a DPI on the path
// would. Its zero value is a clear path.
type fakeDPI struct {
	// blocked is the outcome of a blocked ClientHello; outPass means none
	// is blocked.
	blocked outcomeKind
	// passChunk is the largest chunk size that gets through, 0 for none.
	passChunk int
	// disorderPasses is set when disordered chunks get through.
	disorderPasses bool
	// hop is the hop the DPI is at, 0 for none.
	hop int
	// unreachable fails every connection.
	unreachable bool
	// residual blocks the benign ClientHello, and every connection once
	// the position check reaches the DPI.
	residual bool
	// fakePass says whether the fake of a variant fools the DPI; nil
	// fools it with none.
	fakePass func(v fakeVariant) bool
	// serverAnswer is the answer to the ClientHello after the fake of a
	// variant in the server check; nil, or a false ok, means the server
	// drops the fake.
	serverAnswer func(v fakeVariant) (o outcome, ok bool)

	mu       sync.Mutex
	attempts []attempt
}

func (f *fakeDPI) attempt(_ context.Context, a attempt) outcome {
	f.mu.Lock()
	f.attempts = append(f.attempts, a)
	f.mu.Unlock()

	pass := outcome{kind: outPass}
	block := outcome{kind: f.blocked}
	if f.blocked == outPass {
		block = pass
	}
	switch a.step {
	case stepConnect:
		if f.unreachable {
			return outcome{kind: outDrop, connectFailed: true}
		}
		return outcome{kind: outPass, rtt: 10 * time.Millisecond}
	case stepUnsplit:
		return block
	case stepChunks:
		if a.size <= f.passChunk {
			return pass
		}
		return block
	case stepDisorder:
		if f.disorderPasses {
			return pass
		}
		return block
	case stepBenign:
		if f.residual {
			return outcome{kind: outDrop}
		}
		return pass
	case stepPositionRST:
		if f.hop > 0 && a.ttl >= f.hop {
			return outcome{kind: outRST}
		}
		return outcome{kind: outDrop}
	case stepPositionSilent:
		if f.hop > 0 && a.ttl >= f.hop {
			return outcome{kind: outDrop}
		}
		return outcome{kind: outPass}
	case stepFake:
		if f.fakePass != nil && f.fakePass(a.variant) {
			return pass
		}
		return block
	case stepServerFake, stepServerFakeHost:
		if f.serverAnswer == nil {
			return pass
		}
		if o, ok := f.serverAnswer(a.variant); ok {
			return o
		}
		return pass
	}
	panic("unknown step")
}

// steps returns the attempts made with step.
func (f *fakeDPI) steps(step dpiStep) []attempt {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []attempt
	for _, a := range f.attempts {
		if a.step == step {
			out = append(out, a)
		}
	}
	return out
}

func testRunner(attempt attemptFunc) *dpiRunner {
	return &dpiRunner{
		timeout:      time.Second,
		hops:         12,
		hopsMeasured: true,
		attempt:      attempt,
		residual: residualWait{
			recheck: 10 * time.Millisecond,
			limit:   50 * time.Millisecond,
		},
	}
}

func TestDPI_Clear(t *testing.T) {
	f := &fakeDPI{}
	got := testRunner(f.attempt).run(context.Background(), "")
	assert.Equal(t, DPIResult{
		Measured: true,
		Block:    BlockResult{State: StepDone, Kind: BlockClear},
	}, got)
	assert.Len(t, f.steps(stepUnsplit), 1)
	assert.Len(t, f.steps(stepBenign), 1, "only the baseline")
	assert.Equal(t, time.Second, f.steps(stepUnsplit)[0].wait)
}

func TestDPI_Unreachable(t *testing.T) {
	f := &fakeDPI{unreachable: true}
	got := testRunner(f.attempt).run(context.Background(), "")
	assert.Equal(t, DPIResult{
		Measured: true,
		Block:    BlockResult{State: StepDone, Kind: BlockUnreachable},
	}, got)
	assert.Empty(t, f.steps(stepUnsplit))
	assert.Len(
		t,
		f.steps(stepConnect),
		connectTries,
		"the connect is tried up to 5 times",
	)

	// The hop measurement connected: failed connects are not taken for an
	// unreachable server.
	f = &fakeDPI{unreachable: true}
	r := testRunner(f.attempt)
	r.reachedTCP = true
	got = r.run(context.Background(), "")
	assert.Equal(t, DPIResult{
		Measured: true,
		Block: BlockResult{
			State:  StepDone,
			Kind:   BlockUnknown,
			Reason: "connect failed",
		},
	}, got)
	assert.Len(t, f.steps(stepConnect), connectTries)
}

func TestDPI_ConnectRetried(t *testing.T) {
	f := &fakeDPI{}
	connects := 0
	r := testRunner(func(ctx context.Context, a attempt) outcome {
		if a.step == stepConnect {
			if connects++; connects < 3 {
				return outcome{kind: outDrop, connectFailed: true}
			}
		}
		return f.attempt(ctx, a)
	})
	got := r.run(context.Background(), "")
	assert.Equal(t, BlockResult{State: StepDone, Kind: BlockClear}, got.Block)
	assert.Equal(t, 3, connects, "stops at the first that completes")
}

func TestDPI_RSTSite(t *testing.T) {
	f := &fakeDPI{blocked: outRST, passChunk: 8, disorderPasses: true, hop: 7}
	got := testRunner(f.attempt).run(context.Background(), "")
	assert.Equal(t, DPIResult{
		Measured: true,
		Block:    BlockResult{State: StepDone, Kind: BlockRST},
		Chunks: ChunksResult{
			State: StepDone, Reassembled: true, PassAt: 8, SmallestBlocked: 11,
		},
		Disorder: DisorderResult{State: StepDone, Pass: true, Size: 11},
		Position: PositionResult{State: StepDone, Hop: 7},
		Fake:     FakeResult{State: StepDone, Reason: "needs root"},
	}, got)

	var sizes []int
	for _, a := range f.steps(stepChunks) {
		sizes = append(sizes, a.size)
	}
	assert.Equal(t, []int{35, 32, 29, 26, 23, 20, 17, 14, 11, 8}, sizes,
		"stops at the first size that passes")
	assert.Equal(t, 2*time.Second, f.steps(stepDisorder)[0].wait, "disorder waits twice")
	assert.Len(t, f.steps(stepBenign), 5,
		"the baseline, and a residual check after each of steps 1-4")
	position := f.steps(stepPositionRST)
	assert.Len(t, position, 7)
	assert.Equal(t, 7, position[len(position)-1].ttl)
	assert.Equal(t, minPositionWait, position[0].wait)
}

func TestDPI_SilentSite(t *testing.T) {
	f := &fakeDPI{blocked: outDrop, hop: 5}
	r := testRunner(f.attempt)
	got := r.run(context.Background(), "")
	assert.Equal(t, DPIResult{
		Measured: true,
		Block:    BlockResult{State: StepDone, Kind: BlockSilent},
		Chunks:   ChunksResult{State: StepDone, Reassembled: true, SmallestBlocked: 2},
		Disorder: DisorderResult{State: StepDone, Size: 2},
		Position: PositionResult{State: StepDone, Reason: "needs root"},
		Fake:     FakeResult{State: StepDone, Reason: "needs root"},
	}, got, "without capture")
	assert.Empty(t, f.steps(stepPositionSilent))

	f = &fakeDPI{blocked: outDrop, hop: 5}
	r = testRunner(f.attempt)
	r.canWatch = true
	got = r.run(context.Background(), "")
	assert.Equal(t, PositionResult{State: StepDone, Hop: 5}, got.Position, "with capture")
}

func TestDPI_NotReassembled(t *testing.T) {
	f := &fakeDPI{blocked: outRST, passChunk: 35, disorderPasses: true}
	got := testRunner(f.attempt).run(context.Background(), "")
	assert.Equal(
		t,
		ChunksResult{State: StepDone, PassAt: 35, SmallestBlocked: 35},
		got.Chunks,
	)
	assert.Equal(t, DisorderResult{State: StepDone, Pass: true, Size: 35}, got.Disorder)
	assert.Equal(t, PositionResult{State: StepDone}, got.Position, "no RST at any TTL")
}

func TestDPI_OtherBlock(t *testing.T) {
	r := testRunner(func(_ context.Context, a attempt) outcome {
		switch a.step {
		case stepConnect, stepBenign:
			return outcome{kind: outPass}
		}
		return outcome{kind: outOther, detail: "TLS alert 40", serverReplied: true}
	})
	got := r.run(context.Background(), "")
	assert.Equal(
		t,
		BlockResult{State: StepDone, Kind: BlockOther, Reason: "TLS alert 40"},
		got.Block,
	)
	assert.Equal(
		t,
		ChunksResult{State: StepDone, Reassembled: true, SmallestBlocked: 2},
		got.Chunks,
	)
	assert.Equal(t,
		PositionResult{State: StepDone, Reason: "block is neither RST nor silent"},
		got.Position)
}

func TestDPI_ResidualBlockAfterSteps(t *testing.T) {
	tcs := []struct {
		name string
		// benignBlockedFrom is the benign ClientHello, from 1 for the
		// baseline, that is the first to be blocked.
		benignBlockedFrom int
		want              DPIResult
	}{
		{
			name:              "after block",
			benignBlockedFrom: 2,
			want: DPIResult{
				Measured: true,
				Block:    BlockResult{State: StepDone, Kind: BlockRST},
				Chunks:   ChunksResult{State: StepSkipped},
				Disorder: DisorderResult{State: StepSkipped},
				Position: PositionResult{State: StepSkipped},
				Fake:     FakeResult{State: StepSkipped},
				Notes:    []string{"residual block after the block check"},
			},
		},
		{
			name:              "after chunks",
			benignBlockedFrom: 3,
			want: DPIResult{
				Measured: true,
				Block:    BlockResult{State: StepDone, Kind: BlockRST},
				Chunks:   ChunksResult{State: StepSkipped},
				Disorder: DisorderResult{State: StepSkipped},
				Position: PositionResult{State: StepSkipped},
				Fake:     FakeResult{State: StepSkipped},
				Notes:    []string{"residual block after the chunks check"},
			},
		},
		{
			name:              "after disorder",
			benignBlockedFrom: 4,
			want: DPIResult{
				Measured: true,
				Block:    BlockResult{State: StepDone, Kind: BlockRST},
				Chunks: ChunksResult{
					State: StepDone, Reassembled: true, PassAt: 8, SmallestBlocked: 11,
				},
				Disorder: DisorderResult{State: StepSkipped},
				Position: PositionResult{State: StepSkipped},
				Fake:     FakeResult{State: StepSkipped},
				Notes:    []string{"residual block after the disorder check"},
			},
		},
		{
			name:              "after position",
			benignBlockedFrom: 5,
			want: DPIResult{
				Measured: true,
				Block:    BlockResult{State: StepDone, Kind: BlockRST},
				Chunks: ChunksResult{
					State: StepDone, Reassembled: true, PassAt: 8, SmallestBlocked: 11,
				},
				Disorder: DisorderResult{State: StepDone, Size: 11},
				Position: PositionResult{State: StepSkipped},
				Fake:     FakeResult{State: StepSkipped},
				Notes:    []string{"residual block after the position check"},
			},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeDPI{blocked: outRST, passChunk: 8, hop: 3}
			benign := 0
			r := testRunner(func(ctx context.Context, a attempt) outcome {
				if a.step == stepBenign {
					if benign++; benign >= tc.benignBlockedFrom {
						return outcome{kind: outDrop}
					}
				}
				return f.attempt(ctx, a)
			})
			assert.Equal(t, tc.want, r.run(context.Background(), ""))
		})
	}
}

func TestDPI_ResidualBlockDuringPosition(t *testing.T) {
	f := &fakeDPI{blocked: outRST, hop: 3}
	r := testRunner(func(ctx context.Context, a attempt) outcome {
		if a.step == stepPositionRST && a.ttl == 3 {
			return outcome{kind: outDrop, connectFailed: true}
		}
		return f.attempt(ctx, a)
	})
	got := r.run(context.Background(), "")
	assert.Equal(t, PositionResult{State: StepSkipped}, got.Position)
	assert.Equal(t, []string{"residual block during the position check"}, got.Notes)
}

func TestDPI_ServerAlertPassesResidualCheck(t *testing.T) {
	f := &fakeDPI{blocked: outRST, hop: 3}
	r := testRunner(func(ctx context.Context, a attempt) outcome {
		if a.step == stepBenign {
			return outcome{kind: outOther, detail: "TLS alert 112", serverReplied: true}
		}
		return f.attempt(ctx, a)
	})
	got := r.run(context.Background(), "")
	assert.Empty(t, got.Notes)
	assert.Equal(t, PositionResult{State: StepDone, Hop: 3}, got.Position)
}

func TestDPI_SilentPosition(t *testing.T) {
	tcs := []struct {
		name string
		hops int
		// answer is the outcome of a try with the given TTL.
		answer func(ttl int) outcome
		want   PositionResult
	}{
		{
			name: "found",
			hops: 6,
			answer: func(ttl int) outcome {
				if ttl >= 4 {
					return outcome{kind: outDrop}
				}
				return outcome{kind: outPass}
			},
			want: PositionResult{State: StepDone, Hop: 4},
		},
		{
			name: "found at the last router",
			hops: 6,
			answer: func(ttl int) outcome {
				if ttl == 6 {
					return outcome{kind: outDrop}
				}
				return outcome{kind: outPass}
			},
			want: PositionResult{State: StepDone, Hop: 6},
		},
		{
			name:   "no dup ACK at TTL 1",
			hops:   6,
			answer: func(int) outcome { return outcome{kind: outDrop} },
			want:   PositionResult{State: StepDone, Reason: "no dup ACK"},
		},
		{
			name:   "no dup ACK with one hop",
			hops:   1,
			answer: func(int) outcome { return outcome{kind: outDrop} },
			want:   PositionResult{State: StepDone, Reason: "no dup ACK"},
		},
		{
			name:   "dup ACK with one hop",
			hops:   1,
			answer: func(int) outcome { return outcome{kind: outPass} },
			want:   PositionResult{State: StepDone, Reason: "per-packet drop"},
		},
		{
			name:   "dup ACK at every TTL",
			hops:   6,
			answer: func(int) outcome { return outcome{kind: outPass} },
			want:   PositionResult{State: StepDone, Reason: "per-packet drop"},
		},
		{
			name:   "inconclusive",
			hops:   6,
			answer: func(int) outcome { return inconclusive },
			want:   PositionResult{State: StepDone, Reason: "could not control TTL"},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			var ttls []int
			r := testRunner(func(_ context.Context, a attempt) outcome {
				ttls = append(ttls, a.ttl)
				return tc.answer(a.ttl)
			})
			r.canWatch = true
			r.hops = tc.hops
			got, attempted := r.position(context.Background(),
				BlockResult{State: StepDone, Kind: BlockSilent}, 0, new([]string))
			assert.Equal(t, tc.want, got)
			assert.True(t, attempted)
			assert.Equal(t, 1, ttls[0], "the calibration at TTL 1 runs")
			assert.LessOrEqual(t, ttls[len(ttls)-1], tc.hops, "TTLs up to the hops")
			if tc.want.Reason == "per-packet drop" {
				assert.Equal(t, tc.hops, ttls[len(ttls)-1], "the last router is tried")
			}
		})
	}
}

func TestDPI_RSTPosition(t *testing.T) {
	var ttls []int
	r := testRunner(func(_ context.Context, a attempt) outcome {
		ttls = append(ttls, a.ttl)
		if a.ttl >= 3 {
			return outcome{kind: outRST}
		}
		return outcome{kind: outDrop}
	})
	got, attempted := r.position(context.Background(),
		BlockResult{State: StepDone, Kind: BlockRST}, 0, new([]string))
	assert.Equal(t, PositionResult{State: StepDone, Hop: 3}, got)
	assert.True(t, attempted)
	assert.Equal(t, []int{1, 2, 3}, ttls, "once per TTL")

	r = testRunner(func(context.Context, attempt) outcome {
		return localOutcome("cannot set TTL")
	})
	got, _ = r.position(context.Background(),
		BlockResult{State: StepDone, Kind: BlockRST}, 0, new([]string))
	assert.Equal(t, PositionResult{State: StepDone, Reason: "cannot set TTL"}, got,
		"a local failure is not a missing RST")

	_, attempted = r.position(context.Background(),
		BlockResult{State: StepDone, Kind: BlockSilent}, 0, new([]string))
	assert.False(t, attempted, "without capture")
}

func TestDPI_ResidualWaitBetweenTargets(t *testing.T) {
	t.Run("cleared", func(t *testing.T) {
		f := &fakeDPI{}
		checks := 0
		r := testRunner(func(ctx context.Context, a attempt) outcome {
			if a.step == stepBenign {
				if checks++; checks <= 2 {
					return outcome{kind: outDrop}
				}
			}
			return f.attempt(ctx, a)
		})
		r.residual = residualWait{recheck: time.Second, limit: 5 * time.Second}
		var events []progressEvent
		r.progress = targetProgress{
			report: func(e progressEvent) { events = append(events, e) },
		}

		got := r.run(context.Background(), "a.test")
		assert.Equal(t, 3, checks)
		assert.Equal(t, BlockResult{State: StepDone, Kind: BlockClear}, got.Block)
		assert.Equal(t, []string{"waited 2s for residual block from a.test"}, got.Notes)

		var waits int
		for _, e := range events {
			if !e.waitStart.IsZero() {
				waits++
				assert.Equal(t, "waiting for residual block", e.phase)
				assert.Equal(t, 5*time.Second, e.waitLimit)
			}
		}
		assert.Equal(t, 2, waits)
	})

	t.Run("clear at once", func(t *testing.T) {
		f := &fakeDPI{}
		got := testRunner(f.attempt).run(context.Background(), "a.test")
		assert.Empty(t, got.Notes)
		assert.Len(t, f.steps(stepBenign), 1)
	})

	t.Run("not cleared", func(t *testing.T) {
		f := &fakeDPI{blocked: outRST, residual: true}
		r := testRunner(f.attempt)
		r.residual = residualWait{recheck: 10 * time.Millisecond, limit: 2 * time.Second}
		start := time.Now()
		got := r.run(context.Background(), "a.test")
		assert.GreaterOrEqual(t, time.Since(start), 2*time.Second)
		assert.Equal(t, DPIResult{
			Measured: true,
			Block:    BlockResult{State: StepSkipped},
			Chunks:   ChunksResult{State: StepSkipped},
			Disorder: DisorderResult{State: StepSkipped},
			Position: PositionResult{State: StepSkipped},
			Notes:    []string{"residual block from a.test (not cleared after 2s)"},
		}, got)
		assert.Len(t, f.steps(stepConnect), 1, "the server is reachable")
		assert.Empty(t, f.steps(stepUnsplit), "no check runs")
	})

	t.Run("interrupted", func(t *testing.T) {
		f := &fakeDPI{residual: true}
		r := testRunner(f.attempt)
		r.residual = residualWait{recheck: time.Minute, limit: time.Hour}
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(50*time.Millisecond, cancel)
		start := time.Now()
		r.run(ctx, "a.test")
		assert.Less(t, time.Since(start), 5*time.Second)
	})
}

func TestDPI_InterruptedStopsAttempts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	f := &fakeDPI{blocked: outRST}
	r := testRunner(func(c context.Context, a attempt) outcome {
		if a.step == stepChunks {
			cancel()
		}
		return f.attempt(c, a)
	})
	r.run(ctx, "")
	assert.Len(t, f.steps(stepChunks), 1)
	assert.Empty(t, f.steps(stepDisorder))
}

func TestDPI_ProgressPhases(t *testing.T) {
	f := &fakeDPI{blocked: outRST, passChunk: 20, hop: 2}
	r := testRunner(f.attempt)
	var phases []string
	r.progress = targetProgress{
		report: func(e progressEvent) { phases = append(phases, e.phase) },
		target: 3,
	}
	r.run(context.Background(), "")
	require.NotEmpty(t, phases)
	assert.Contains(t, phases, "dpi block")
	assert.Contains(t, phases, "dpi chunks 20 bytes")
	assert.Contains(t, phases, "dpi disorder 23 bytes")
	assert.Contains(t, phases, "dpi position TTL 2")
	assert.Contains(t, phases, "dpi residual check")
}

func TestPositionWait(t *testing.T) {
	assert.Equal(t, minPositionWait, positionWait(time.Millisecond, 2*time.Second))
	assert.Equal(
		t,
		1200*time.Millisecond,
		positionWait(250*time.Millisecond, 2*time.Second),
	)
	assert.Equal(t, 2*time.Second, positionWait(time.Second, 2*time.Second))
	assert.Equal(
		t,
		300*time.Millisecond,
		positionWait(time.Millisecond, 300*time.Millisecond),
	)
}

func TestDPIHops(t *testing.T) {
	assert.Equal(t, 11, dpiHops(TCPResult{Status: TCPMeasured, Hops: 11}, 32))
	assert.Equal(t, 32, dpiHops(TCPResult{Status: TCPAboveMax, Hops: 31}, 32))
	assert.Equal(t, 32, dpiHops(TCPResult{Status: TCPNoHandshake}, 32))
}

func TestDPI_UnreachableBeforeResidualWait(t *testing.T) {
	f := &fakeDPI{unreachable: true, residual: true}
	start := time.Now()
	got := testRunner(f.attempt).run(context.Background(), "a.test")
	assert.Less(t, time.Since(start), time.Second, "no residual wait")
	assert.Equal(t, DPIResult{
		Measured: true,
		Block:    BlockResult{State: StepDone, Kind: BlockUnreachable},
	}, got)
	assert.Empty(t, f.steps(stepBenign))
}

func TestDPI_Baseline(t *testing.T) {
	// A front end that closes connections for names it does not serve.
	f := &fakeDPI{blocked: outRST, passChunk: 8, disorderPasses: true, hop: 3}
	closed := outcome{kind: outOther, detail: "closed"}
	r := testRunner(func(ctx context.Context, a attempt) outcome {
		if a.step == stepBenign {
			return closed
		}
		return f.attempt(ctx, a)
	})
	got := r.run(context.Background(), "")
	assert.Equal(t, []string{"benign baseline: closed"}, got.Notes)
	assert.Equal(t, PositionResult{State: StepDone, Hop: 3}, got.Position,
		"residual checks that match the baseline pass")

	// After the block check, the benign ClientHello is reset instead.
	benign := 0
	r = testRunner(func(ctx context.Context, a attempt) outcome {
		if a.step == stepBenign {
			if benign++; benign > 1 {
				return outcome{kind: outRST}
			}
			return closed
		}
		return f.attempt(ctx, a)
	})
	got = r.run(context.Background(), "")
	assert.Equal(t, BlockResult{State: StepDone, Kind: BlockRST}, got.Block,
		"the block line keeps its value")
	assert.Equal(t, StepSkipped, got.Chunks.State)
	assert.Equal(t,
		[]string{"benign baseline: closed", "residual block after the block check"},
		got.Notes)

	// A TLS alert and a ServerHello are both the server answering.
	benign = 0
	r = testRunner(func(ctx context.Context, a attempt) outcome {
		if a.step == stepBenign {
			if benign++; benign == 1 {
				return outcome{kind: outOther, detail: "TLS alert 112", serverReplied: true}
			}
		}
		return f.attempt(ctx, a)
	})
	got = r.run(context.Background(), "")
	assert.Empty(t, got.Notes)
}

func TestDPI_LocalFailures(t *testing.T) {
	cannotBuild := localOutcome("build ClientHello: boom")
	t.Run("block", func(t *testing.T) {
		r := testRunner(func(_ context.Context, a attempt) outcome {
			if a.step == stepConnect || a.step == stepBenign {
				return outcome{kind: outPass}
			}
			return cannotBuild
		})
		got := r.run(context.Background(), "")
		assert.Equal(t, DPIResult{
			Measured: true,
			Block: BlockResult{
				State: StepDone, Kind: BlockUnknown, Reason: "build ClientHello: boom",
			},
		}, got)
	})
	t.Run("connect", func(t *testing.T) {
		connects := 0
		r := testRunner(func(_ context.Context, a attempt) outcome {
			if a.step == stepConnect {
				connects++
			}
			return localOutcome("local error EMFILE")
		})
		got := r.run(context.Background(), "")
		assert.Equal(t,
			BlockResult{State: StepDone, Kind: BlockUnknown, Reason: "local error EMFILE"},
			got.Block)
		assert.Equal(t, 1, connects, "a local failure is not retried")
	})
	t.Run("chunks and disorder", func(t *testing.T) {
		f := &fakeDPI{blocked: outRST, hop: 2}
		r := testRunner(func(ctx context.Context, a attempt) outcome {
			switch {
			case a.step == stepChunks && a.size <= 20:
				return cannotBuild
			case a.step == stepDisorder:
				return localOutcome("cannot set TTL")
			}
			return f.attempt(ctx, a)
		})
		got := r.run(context.Background(), "")
		assert.Equal(t, ChunksResult{
			State: StepDone, Reassembled: true, SmallestBlocked: 23,
			Reason: "build ClientHello: boom",
		}, got.Chunks)
		assert.Equal(t,
			DisorderResult{State: StepDone, Size: 23, Reason: "cannot set TTL"},
			got.Disorder, "not counted as blocked")
		assert.Equal(t, PositionResult{State: StepDone, Hop: 2}, got.Position)
	})
}
