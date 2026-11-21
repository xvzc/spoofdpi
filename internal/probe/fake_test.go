package probe

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

// fakesReady is the fakesReady of a runner that can send fake packets.
func fakesReady() string { return "" }

// fooled returns a fakePass: the ttl fake fools the DPI when ttl is set,
// the seq and ack offset fakes up to magnitudes seq and ack, and the
// bad_md5 fake when md5 is set.
func fooled(ttl bool, seq, ack int64, md5 bool) func(fakeVariant) bool {
	return func(v fakeVariant) bool {
		switch {
		case v.seqOffset != 0:
			return -v.seqOffset <= seq
		case v.ackOffset != 0:
			return -v.ackOffset <= ack
		case v.badMD5:
			return md5
		}
		return ttl
	}
}

// allFakesPass fools the DPI with every fake.
func allFakesPass() func(fakeVariant) bool {
	return fooled(true, maxOffset, maxOffset, true)
}

func fakeRunner(f *fakeDPI) *dpiRunner {
	r := testRunner(f.attempt)
	r.fakesReady = fakesReady
	return r
}

func TestDPI_Fake(t *testing.T) {
	f := &fakeDPI{
		blocked:        outRST,
		passChunk:      8,
		disorderPasses: true,
		hop:            7,
		fakePass:       fooled(true, 5000, maxOffset, false),
	}
	got := fakeRunner(f).run(context.Background(), "")
	assert.Equal(t, FakeResult{
		State:     StepDone,
		TTL:       FakeVariantResult{State: StepDone, Pass: true},
		SeqOffset: FakeOffsetResult{State: StepDone, MaxPass: 4096, MinFail: 8192},
		AckOffset: FakeOffsetResult{State: StepDone, MaxPass: maxOffset},
		BadMD5:    FakeVariantResult{State: StepDone},
	}, got.Fake)
	assert.Empty(t, got.Notes)

	var tried []fakeVariant
	for _, a := range f.steps(stepFake) {
		assert.Equal(t, 7, a.ttl, "the fakes die at the DPI's hop")
		assert.Equal(t, testRunner(nil).timeout, a.wait)
		tried = append(tried, a.variant)
	}
	want := []fakeVariant{ttlVariant}
	// The powers of two up to the first that fails, and the one after it.
	for m := int64(1); m <= 16384; m *= 2 {
		want = append(want, seqVariant(m))
	}
	for m := int64(1); m <= maxOffset; m *= 2 {
		want = append(want, ackVariant(m))
	}
	want = append(want, badMD5Variant)
	assert.Equal(t, want, tried, "once each, in order")
	assert.Len(t, f.steps(stepBenign), 6, "a residual check after the fake check too")
}

func TestDPI_FakeOffsetSearch(t *testing.T) {
	tcs := []struct {
		name     string
		fakePass func(fakeVariant) bool
		// attempt, if set, answers the fakes it has an answer for.
		attempt func(a attempt) (outcome, bool)
		wantSeq FakeOffsetResult
		wantAck FakeOffsetResult
	}{
		{
			name:     "fails at -1",
			fakePass: fooled(true, 0, 66000, true),
			wantSeq:  FakeOffsetResult{State: StepDone, MinFail: 1},
			wantAck:  FakeOffsetResult{State: StepDone, MaxPass: 65536, MinFail: 131072},
		},
		{
			name:     "every offset",
			fakePass: allFakesPass(),
			wantSeq:  FakeOffsetResult{State: StepDone, MaxPass: maxOffset},
			wantAck:  FakeOffsetResult{State: StepDone, MaxPass: maxOffset},
		},
		{
			name: "passes again past a failing offset",
			fakePass: func(v fakeVariant) bool {
				if v.seqOffset == 0 {
					// ttl and bad_md5 pass, the ack offsets do not.
					return v.ackOffset == 0
				}
				m := -v.seqOffset
				return m <= 4 || m >= 16
			},
			wantSeq: FakeOffsetResult{State: StepUnstable},
			wantAck: FakeOffsetResult{State: StepDone, MinFail: 1},
		},
		{
			name:     "fails on this host",
			fakePass: allFakesPass(),
			attempt: func(a attempt) (outcome, bool) {
				if a.variant == ackVariant(8) {
					return localOutcome("seq not learned"), true
				}
				return outcome{}, false
			},
			wantSeq: FakeOffsetResult{State: StepDone, MaxPass: maxOffset},
			wantAck: FakeOffsetResult{State: StepDone, Reason: "seq not learned"},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeDPI{blocked: outRST, hop: 3, fakePass: tc.fakePass}
			r := fakeRunner(f)
			r.attempt = func(ctx context.Context, a attempt) outcome {
				if tc.attempt != nil && a.step == stepFake {
					if o, ok := tc.attempt(a); ok {
						return o
					}
				}
				return f.attempt(ctx, a)
			}
			got := r.run(context.Background(), "")
			assert.Equal(t, tc.wantSeq, got.Fake.SeqOffset)
			assert.Equal(t, tc.wantAck, got.Fake.AckOffset)
			assert.Equal(t, StepDone, got.Fake.BadMD5.State, "bad_md5 is still tried")
		})
	}
}

func TestDPI_FakeTTL(t *testing.T) {
	// No RST at any TTL: the position is unknown.
	f := &fakeDPI{blocked: outRST, fakePass: allFakesPass()}
	got := fakeRunner(f).run(context.Background(), "")
	assert.Equal(t, PositionResult{State: StepDone}, got.Position)
	assert.Equal(
		t,
		FakeOffsetResult{State: StepDone, MaxPass: maxOffset},
		got.Fake.SeqOffset,
	)
	assert.Equal(t, 11, f.steps(stepFake)[0].ttl, "the hop count minus 1")

	tcs := []struct {
		name         string
		hops         int
		hopsMeasured bool
		pos          PositionResult
		want         int
		wantReason   string
	}{
		{
			name: "position", hops: 12, hopsMeasured: true,
			pos: PositionResult{State: StepDone, Hop: 7}, want: 7,
		},
		{
			name: "no position", hops: 12, hopsMeasured: true,
			pos: PositionResult{State: StepDone, Reason: "needs root"}, want: 11,
		},
		{name: "one hop", hops: 1, hopsMeasured: true, want: 1},
		{
			name: "position without a measured hop count", hops: 32,
			pos: PositionResult{State: StepDone, Hop: 7}, wantReason: "hop count unknown",
		},
		{
			name:         "local link",
			hops:         0,
			hopsMeasured: true,
			wantReason:   "server on local link",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			r := testRunner(nil)
			r.hops, r.hopsMeasured = tc.hops, tc.hopsMeasured
			ttl, reason := r.fakeTTL(tc.pos)
			assert.Equal(t, tc.want, ttl)
			assert.Equal(t, tc.wantReason, reason)
		})
	}
}

func TestDPI_FakeWithoutTTL(t *testing.T) {
	f := &fakeDPI{blocked: outRST, hop: 3, fakePass: allFakesPass()}
	r := fakeRunner(f)
	r.hopsMeasured = false
	got := r.run(context.Background(), "")
	assert.Equal(t, FakeResult{State: StepDone, Reason: "hop count unknown"}, got.Fake)
	assert.Empty(t, f.steps(stepFake))
	assert.Len(t, f.steps(stepBenign), 5, "no residual check without fakes")
}

func TestDPI_FakeTTLFails(t *testing.T) {
	f := &fakeDPI{blocked: outRST, hop: 3}
	got := fakeRunner(f).run(context.Background(), "")
	assert.Equal(t, FakeResult{
		State: StepDone, TTL: FakeVariantResult{State: StepDone},
	}, got.Fake, "the other fakes are left out")
	assert.Len(t, f.steps(stepFake), 1)
}

func TestDPI_FakeReachesServer(t *testing.T) {
	f := &fakeDPI{blocked: outRST, hop: 3}
	r := fakeRunner(f)
	r.attempt = func(ctx context.Context, a attempt) outcome {
		if a.step == stepFake {
			return outcome{kind: outOther, serverReplied: true, answeredFake: true}
		}
		return f.attempt(ctx, a)
	}
	got := r.run(context.Background(), "")
	assert.Equal(t, FakeResult{
		State: StepDone,
		TTL:   FakeVariantResult{State: StepDone, Reason: "fake reached server"},
	}, got.Fake)
}

func TestDPI_FakeNotReady(t *testing.T) {
	f := &fakeDPI{blocked: outRST, hop: 3, fakePass: allFakesPass()}
	r := fakeRunner(f)
	r.fakesReady = func() string { return "fake packets unavailable" }
	got := r.run(context.Background(), "")
	assert.Equal(
		t,
		FakeResult{State: StepDone, Reason: "fake packets unavailable"},
		got.Fake,
	)
	assert.Empty(t, f.steps(stepFake))
}

func TestDPI_FakeResidualBlock(t *testing.T) {
	f := &fakeDPI{blocked: outRST, hop: 3, fakePass: allFakesPass()}
	benign := 0
	r := fakeRunner(f)
	r.attempt = func(ctx context.Context, a attempt) outcome {
		// The baseline and the residual checks after the block, chunks,
		// disorder and position checks are answered; the one after the
		// fake check is not.
		if a.step == stepBenign {
			if benign++; benign > 5 {
				return outcome{kind: outDrop}
			}
		}
		return f.attempt(ctx, a)
	}
	got := r.run(context.Background(), "")
	assert.Equal(t, FakeResult{State: StepSkipped}, got.Fake)
	assert.Equal(t, PositionResult{State: StepDone, Hop: 3}, got.Position)
	assert.Equal(t, []string{"residual block after the fake check"}, got.Notes)
	assert.True(t, r.residualLeft)
}

func TestDPI_FakeAfterPositionSkipped(t *testing.T) {
	f := &fakeDPI{blocked: outRST, hop: 3, fakePass: allFakesPass()}
	r := fakeRunner(f)
	r.attempt = func(ctx context.Context, a attempt) outcome {
		if a.step == stepPositionRST && a.ttl == 3 {
			return outcome{kind: outDrop, connectFailed: true}
		}
		return f.attempt(ctx, a)
	}
	got := r.run(context.Background(), "")
	assert.Equal(t, PositionResult{State: StepSkipped}, got.Position)
	assert.Equal(t, FakeResult{State: StepSkipped}, got.Fake)
	assert.Empty(t, f.steps(stepFake))
}

func TestDPI_FakeOnlyForCensored(t *testing.T) {
	f := &fakeDPI{fakePass: allFakesPass()}
	got := fakeRunner(f).run(context.Background(), "")
	assert.Equal(t, FakeResult{}, got.Fake, "clear")

	f = &fakeDPI{unreachable: true, fakePass: allFakesPass()}
	r := fakeRunner(f)
	r.reachedTCP = true
	got = r.run(context.Background(), "")
	assert.Equal(t, FakeResult{}, got.Fake, "unknown")
}

func TestDPI_FakeInterrupted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	f := &fakeDPI{blocked: outRST, hop: 3, fakePass: allFakesPass()}
	r := fakeRunner(f)
	r.attempt = func(c context.Context, a attempt) outcome {
		if a.step == stepFake {
			cancel()
		}
		return f.attempt(c, a)
	}
	r.run(ctx, "")
	assert.Len(t, f.steps(stepFake), 1)
}

func TestDPI_FakeProgressPhases(t *testing.T) {
	f := &fakeDPI{blocked: outRST, hop: 3, fakePass: allFakesPass()}
	r := fakeRunner(f)
	var phases []string
	r.progress = targetProgress{
		report: func(e progressEvent) { phases = append(phases, e.phase) },
	}
	r.run(context.Background(), "")
	assert.Contains(t, phases, "preparing fake packets")
	assert.Contains(t, phases, "dpi fake ttl")
	assert.Contains(t, phases, "dpi fake seq_offset -4096")
	assert.Contains(t, phases, "dpi fake ack_offset -2147483648")
	assert.Contains(t, phases, "dpi fake bad_md5")
	assert.Equal(t, "dpi residual check", phases[len(phases)-1])
}
