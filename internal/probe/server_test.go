package probe

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// runWithServer runs the DPI checks, then the server check, as
// measureDPI does.
func runWithServer(
	ctx context.Context,
	r *dpiRunner,
	prev string,
) (DPIResult, ServerResult) {
	res := r.run(ctx, prev)
	return res, r.server(ctx, &res)
}

// allDrop is the server check's result for a server that drops every
// fake.
func allDrop(badSNI string) ServerResult {
	return ServerResult{
		Measured:  true,
		State:     StepDone,
		BadSNI:    badSNI,
		SeqOffset: ServerOffsetResult{State: StepDone, DropsFrom: 1},
		AckOffset: ServerOffsetResult{State: StepDone, DropsFrom: 1},
		BadMD5:    ServerVariantResult{State: StepDone, Drops: true},
	}
}

// allDropTries is the number of attempts of the server check of a server
// that drops every fake: the offsets -1 and -2 of each search, and
// bad_md5.
const allDropTries = 2 + 2 + 1

// breaksBelow returns a serverAnswer: the server answers with o after the
// seq offset fakes of magnitudes below seq and the ack offset fakes below
// ack, and drops the other fakes.
func breaksBelow(seq, ack int64, o outcome) func(fakeVariant) (outcome, bool) {
	return func(v fakeVariant) (outcome, bool) {
		m := -(v.seqOffset + v.ackOffset)
		switch {
		case v.seqOffset != 0:
			return o, m < seq
		case v.ackOffset != 0:
			return o, m < ack
		}
		return outcome{}, false
	}
}

func TestServer_Clear(t *testing.T) {
	f := &fakeDPI{}
	r := fakeRunner(f)
	_, got := runWithServer(context.Background(), r, "")
	assert.Equal(t, allDrop("answers"), got)

	assert.Empty(t, f.steps(stepServerFake))
	tries := f.steps(stepServerFakeHost)
	assert.Len(t, tries, allDropTries, "with the site's own ClientHello")
	want := []fakeVariant{
		seqVariant(1), seqVariant(2), ackVariant(1), ackVariant(2), badMD5Variant,
	}
	for i, a := range tries {
		assert.Equal(t, want[i], a.variant, "once each")
		assert.Equal(t, time.Second, a.wait)
		assert.Equal(t, minPositionWait, a.linger, "four round trips, at least 500ms")
	}
	assert.Len(t, f.steps(stepBenign), 2, "the baseline and the residual check")
}

func TestServer_ClearRejectsUnknownSNI(t *testing.T) {
	// The baseline is not used: the site's own ClientHello is answered.
	f := &fakeDPI{serverAnswer: func(v fakeVariant) (outcome, bool) {
		return outcome{
			kind:          outOther,
			detail:        "answered fake",
			serverReplied: true,
			answeredFake:  true,
		}, v.badMD5
	}}
	r := fakeRunner(f)
	r.attempt = func(ctx context.Context, a attempt) outcome {
		if a.step == stepBenign {
			return outcome{kind: outOther, detail: "TLS alert 112", serverReplied: true}
		}
		return f.attempt(ctx, a)
	}
	_, got := runWithServer(context.Background(), r, "")
	assert.Equal(t, "alert 112 (unrecognized_name)", got.BadSNI)
	assert.Empty(t, got.Reason)
	assert.Equal(t, ServerOffsetResult{State: StepDone, DropsFrom: 1}, got.SeqOffset)
	assert.Equal(t,
		ServerVariantResult{State: StepDone, Break: "bad sni"},
		got.BadMD5, "the fake's session ID echoed")
	assert.Len(t, f.steps(stepServerFakeHost), allDropTries)
}

func TestServer_Censored(t *testing.T) {
	f := &fakeDPI{blocked: outRST, hop: 3, fakePass: allFakesPass()}
	res, got := runWithServer(context.Background(), fakeRunner(f), "")
	assert.Equal(t, allDrop("answers"), got)
	assert.Empty(t, res.Notes)
	assert.Len(t, f.steps(stepServerFake), allDropTries, "with the benign ClientHello")
	assert.Empty(t, f.steps(stepServerFakeHost))
}

func TestServer_CensoredRejectsUnknownSNI(t *testing.T) {
	for _, benign := range []outcome{
		{kind: outOther, detail: "TLS alert 112", serverReplied: true},
		{kind: outOther, detail: "closed"},
		{kind: outRST},
	} {
		f := &fakeDPI{blocked: outRST, hop: 3, fakePass: allFakesPass()}
		r := testRunner(nil)
		r.attempt = func(ctx context.Context, a attempt) outcome {
			if a.step == stepBenign {
				return benign
			}
			return f.attempt(ctx, a)
		}
		_, got := runWithServer(context.Background(), r, "")
		assert.Equal(t, ServerResult{
			Measured: true, State: StepDone,
			BadSNI: badSNIValue(benign), Reason: "server rejects unknown SNI",
		}, got, "%s, even without root", benign.detail)
		assert.Empty(t, f.steps(stepServerFake))
	}
}

func TestServer_OffsetSearch(t *testing.T) {
	rst := outcome{kind: outRST}
	closed := outcome{kind: outOther, detail: "closed"}
	tcs := []struct {
		name         string
		serverAnswer func(fakeVariant) (outcome, bool)
		// attempt, if set, answers the fakes it has an answer for.
		attempt func(a attempt) (outcome, bool)
		wantSeq ServerOffsetResult
		wantAck ServerOffsetResult
	}{
		{
			name:         "drops from a magnitude on",
			serverAnswer: breaksBelow(517, 66000, closed),
			wantSeq: ServerOffsetResult{
				State: StepDone, DropsFrom: 1024, LastBreak: 512, Break: "closed",
			},
			wantAck: ServerOffsetResult{
				State: StepDone, DropsFrom: 131072, LastBreak: 65536, Break: "closed",
			},
		},
		{
			name: "the break nearest the boundary",
			serverAnswer: func(v fakeVariant) (outcome, bool) {
				switch m := -v.seqOffset; {
				case m == 0:
					return outcome{}, false
				case m < 100:
					return rst, true
				case m < 10000:
					return outcome{
						kind:          outOther,
						detail:        "TLS alert 10",
						serverReplied: true,
					}, true
				}
				return outcome{}, false
			},
			wantSeq: ServerOffsetResult{
				State: StepDone, DropsFrom: 16384, LastBreak: 8192, Break: "alert 10",
			},
			wantAck: ServerOffsetResult{State: StepDone, DropsFrom: 1},
		},
		{
			name: "breaks at every offset",
			serverAnswer: breaksBelow(maxOffset+1, 0, outcome{
				kind: outOther, serverReplied: true, answeredFake: true,
			}),
			wantSeq: ServerOffsetResult{
				State: StepDone, LastBreak: maxOffset, Break: "bad sni",
			},
			wantAck: ServerOffsetResult{State: StepDone, DropsFrom: 1},
		},
		{
			name: "breaks again past a dropped offset",
			serverAnswer: func(v fakeVariant) (outcome, bool) {
				m := -v.ackOffset
				return rst, m != 0 && (m < 8 || m >= 16)
			},
			wantSeq: ServerOffsetResult{State: StepDone, DropsFrom: 1},
			wantAck: ServerOffsetResult{State: StepUnstable},
		},
		{
			name:         "fails on this host",
			serverAnswer: breaksBelow(1000, 1000, rst),
			attempt: func(a attempt) (outcome, bool) {
				if a.variant == ackVariant(4) {
					return localOutcome("seq not learned"), true
				}
				return outcome{}, false
			},
			wantSeq: ServerOffsetResult{
				State: StepDone, DropsFrom: 1024, LastBreak: 512, Break: "reset",
			},
			wantAck: ServerOffsetResult{State: StepDone, Reason: "seq not learned"},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeDPI{serverAnswer: tc.serverAnswer}
			r := fakeRunner(f)
			r.attempt = func(ctx context.Context, a attempt) outcome {
				if tc.attempt != nil && a.step == stepServerFakeHost {
					if o, ok := tc.attempt(a); ok {
						return o
					}
				}
				return f.attempt(ctx, a)
			}
			_, got := runWithServer(context.Background(), r, "")
			assert.Equal(t, tc.wantSeq, got.SeqOffset)
			assert.Equal(t, tc.wantAck, got.AckOffset)
			assert.Equal(t, ServerVariantResult{State: StepDone, Drops: true}, got.BadMD5)
		})
	}
}

func TestServer_BadMD5Breaks(t *testing.T) {
	f := &fakeDPI{serverAnswer: func(v fakeVariant) (outcome, bool) {
		return outcome{kind: outOther, detail: "closed"}, v.badMD5
	}}
	_, got := runWithServer(context.Background(), fakeRunner(f), "")
	assert.Equal(t, ServerVariantResult{State: StepDone, Break: "closed"}, got.BadMD5)
}

func TestServer_ExactAnswer(t *testing.T) {
	// The benign ClientHello alone gets a ServerHello; after a fake, any
	// other answer breaks, a TLS alert too.
	f := &fakeDPI{blocked: outRST, hop: 3, serverAnswer: breaksBelow(10, 0, outcome{
		kind: outOther, detail: "TLS alert 112", serverReplied: true,
	})}
	_, got := runWithServer(context.Background(), fakeRunner(f), "")
	assert.Equal(t, "answers", got.BadSNI)
	assert.Equal(
		t,
		ServerOffsetResult{
			State:     StepDone,
			DropsFrom: 16,
			LastBreak: 8,
			Break:     "alert 112",
		},
		got.SeqOffset,
	)
	assert.Equal(t, ServerOffsetResult{State: StepDone, DropsFrom: 1}, got.AckOffset)
}

func TestServerVariantResult(t *testing.T) {
	tcs := []struct {
		name string
		o    outcome
		want ServerVariantResult
	}{
		{
			name: "drops",
			o:    outcome{kind: outPass},
			want: ServerVariantResult{State: StepDone, Drops: true},
		},
		{
			name: "breaks",
			o:    outcome{kind: outRST},
			want: ServerVariantResult{State: StepDone, Break: "reset"},
		},
		{
			name: "local",
			o:    localOutcome("seq not learned"),
			want: ServerVariantResult{State: StepDone, Reason: "seq not learned"},
		},
		{
			name: "an alert",
			o:    outcome{kind: outOther, detail: "TLS alert 50", serverReplied: true},
			want: ServerVariantResult{State: StepDone, Break: "alert 50"},
		},
		{
			name: "the fake answered",
			o:    outcome{kind: outOther, serverReplied: true, answeredFake: true},
			want: ServerVariantResult{State: StepDone, Break: "bad sni"},
		},
		{
			name: "unexpected reply",
			o:    outcome{kind: outOther, detail: "unexpected reply"},
			want: ServerVariantResult{State: StepDone, Break: "unexpected reply"},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, serverVariantResult(tc.o))
		})
	}
}

func TestBadSNIValue(t *testing.T) {
	assert.Equal(t, "answers", badSNIValue(outcome{kind: outPass}))
	assert.Equal(t, "reset", badSNIValue(outcome{kind: outRST}))
	assert.Equal(t, "silent", badSNIValue(outcome{kind: outDrop}))
	assert.Equal(t, "closed", badSNIValue(outcome{kind: outOther, detail: "closed"}))
	assert.Equal(t, "unknown (local error EMFILE)",
		badSNIValue(localOutcome("local error EMFILE")))
	assert.Equal(t, "alert 112 (unrecognized_name)", badSNIValue(
		outcome{kind: outOther, detail: "TLS alert 112", serverReplied: true}))
	assert.Equal(t, "alert 250", badSNIValue(
		outcome{kind: outOther, detail: "TLS alert 250", serverReplied: true}))
	assert.Equal(t, "alert", badSNIValue(
		outcome{kind: outOther, detail: "TLS alert", serverReplied: true}))
}

func TestServer_BaselineAfterResidualWait(t *testing.T) {
	f := &fakeDPI{}
	r := fakeRunner(f)
	r.attempt = func(ctx context.Context, a attempt) outcome {
		if a.step == stepBenign {
			return outcome{kind: outOther, detail: "TLS alert 112", serverReplied: true}
		}
		return f.attempt(ctx, a)
	}
	_, got := runWithServer(context.Background(), r, "a.test")
	assert.Equal(t, "alert 112 (unrecognized_name)", got.BadSNI,
		"the answer that cleared the wait")
	assert.Equal(t, allDrop("alert 112 (unrecognized_name)"), got, "a clear site")
}

func TestServer_ResidualBlock(t *testing.T) {
	f := &fakeDPI{}
	benign := 0
	r := fakeRunner(f)
	r.attempt = func(ctx context.Context, a attempt) outcome {
		if a.step == stepBenign {
			if benign++; benign > 1 {
				return outcome{kind: outDrop}
			}
		}
		return f.attempt(ctx, a)
	}
	res, got := runWithServer(context.Background(), r, "")
	assert.Equal(t, ServerResult{Measured: true, State: StepSkipped}, got)
	assert.Equal(t, []string{"residual block after the server check"}, res.Notes)
}

func TestServer_AfterResidualBlock(t *testing.T) {
	f := &fakeDPI{blocked: outRST, passChunk: 8, hop: 3}
	benign := 0
	r := fakeRunner(f)
	r.attempt = func(ctx context.Context, a attempt) outcome {
		if a.step == stepBenign {
			if benign++; benign == 3 {
				return outcome{kind: outDrop}
			}
		}
		return f.attempt(ctx, a)
	}
	res, got := runWithServer(context.Background(), r, "")
	assert.Equal(t, ServerResult{Measured: true, State: StepSkipped}, got)
	assert.Equal(t, []string{"residual block after the chunks check"}, res.Notes)
	assert.Empty(t, f.steps(stepServerFake))
}

func TestServer_NotMeasured(t *testing.T) {
	tcs := []struct {
		name string
		f    *fakeDPI
		prev string
	}{
		{name: "unreachable", f: &fakeDPI{unreachable: true}},
		{name: "residual block not cleared", f: &fakeDPI{residual: true}, prev: "a.test"},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			_, got := runWithServer(context.Background(), fakeRunner(tc.f), tc.prev)
			assert.Equal(t, ServerResult{}, got)
			assert.Empty(t, tc.f.steps(stepServerFake))
		})
	}

	r := fakeRunner(&fakeDPI{})
	r.attempt = func(_ context.Context, a attempt) outcome {
		if a.step == stepConnect || a.step == stepBenign {
			return outcome{kind: outPass}
		}
		return localOutcome("build ClientHello: boom")
	}
	_, got := runWithServer(context.Background(), r, "")
	assert.Equal(t, ServerResult{}, got, "unknown")
}

func TestServer_NeedsRoot(t *testing.T) {
	f := &fakeDPI{}
	_, got := runWithServer(context.Background(), testRunner(f.attempt), "")
	assert.Equal(
		t,
		ServerResult{
			Measured: true, State: StepDone, BadSNI: "answers", Reason: "needs root",
		},
		got,
	)
	assert.Empty(t, f.steps(stepServerFakeHost))
}

func TestServer_Interrupted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	f := &fakeDPI{}
	r := fakeRunner(f)
	r.attempt = func(c context.Context, a attempt) outcome {
		if a.step == stepServerFakeHost {
			cancel()
		}
		return f.attempt(c, a)
	}
	runWithServer(ctx, r, "")
	assert.Len(t, f.steps(stepServerFakeHost), 1)
}

func TestServer_ProgressPhases(t *testing.T) {
	r := fakeRunner(&fakeDPI{})
	var phases []string
	r.progress = targetProgress{
		report: func(e progressEvent) { phases = append(phases, e.phase) },
	}
	runWithServer(context.Background(), r, "")
	assert.Contains(t, phases, "server preparing fake packets")
	assert.Contains(t, phases, "server seq_offset -1")
	assert.Contains(t, phases, "server ack_offset -2")
	assert.Contains(t, phases, "server bad_md5")
	assert.Equal(t, "dpi residual check", phases[len(phases)-1])
}

func TestServer_LocalBaseline(t *testing.T) {
	local := localOutcome("local error EMFILE")
	withLocalBaseline := func(f *fakeDPI) *dpiRunner {
		r := fakeRunner(f)
		benign := 0
		r.attempt = func(ctx context.Context, a attempt) outcome {
			// Only the baseline fails on this host.
			if a.step == stepBenign {
				if benign++; benign == 1 {
					return local
				}
				return outcome{kind: outOther, detail: "local error EMFILE"}
			}
			return f.attempt(ctx, a)
		}
		return r
	}

	f := &fakeDPI{blocked: outRST, hop: 3}
	_, got := runWithServer(context.Background(), withLocalBaseline(f), "")
	assert.Equal(t, ServerResult{
		Measured: true, State: StepDone,
		BadSNI: "unknown (local error EMFILE)", Reason: "local error EMFILE",
	}, got, "censored: the server is not blamed")
	assert.Empty(t, f.steps(stepServerFake))

	f = &fakeDPI{}
	_, got = runWithServer(context.Background(), withLocalBaseline(f), "")
	assert.Equal(t, "unknown (local error EMFILE)", got.BadSNI)
	assert.Empty(t, got.Reason)
	assert.Equal(t, allDrop("unknown (local error EMFILE)"), got,
		"clear: the site's own ClientHello")
}
