package probe

import (
	"context"
	"fmt"
	"time"
)

// The residual block wait: before the DPI checks of a target at the
// address of one checked before, how often the residual check is
// repeated while it is blocked, and for how long.
const (
	defaultResidualRecheck = 5 * time.Second
	defaultResidualLimit   = 60 * time.Second
)

// connectTries is the most attempts of the connect that starts the DPI
// checks. Every other attempt of the DPI checks is made once.
const connectTries = 5

// chunkSizes are the chunk sizes of the chunks check, largest first.
var chunkSizes = []int{35, 32, 29, 26, 23, 20, 17, 14, 11, 8, 5, 2}

// dpiStep is the kind of an attempt of the DPI checks.
type dpiStep int

const (
	// stepConnect connects, without sending anything.
	stepConnect dpiStep = iota
	// stepUnsplit sends the ClientHello in one write.
	stepUnsplit
	// stepChunks sends it in chunks of size bytes.
	stepChunks
	// stepDisorder sends it in chunks of size bytes with disorder.
	stepDisorder
	// stepBenign sends a ClientHello for benignSNI in one write.
	stepBenign
	// stepPositionRST sends the ClientHello with TTL ttl, for a reset.
	stepPositionRST
	// stepPositionSilent sends the ClientHello with TTL ttl, then a byte
	// past it that reaches the server; it passes when the server's
	// duplicate ACK of that byte comes back.
	stepPositionSilent
	// stepFake sends a fake ClientHello crafted as variant with TTL ttl,
	// then the ClientHello in one write.
	stepFake
	// stepServerFake sends a fake ClientHello crafted as variant with
	// restoredTTL, then a ClientHello for benignSNI in one write.
	stepServerFake
	// stepServerFakeHost is stepServerFake with the ClientHello for the
	// target's host.
	stepServerFakeHost
)

// attempt is one attempt of the DPI checks.
type attempt struct {
	step    dpiStep
	size    int
	ttl     int
	variant fakeVariant
	// wait bounds the wait for the answer.
	wait time.Duration
	// linger is how long stepServerFake and stepServerFakeHost keep
	// reading after a ServerHello that does not tell which ClientHello it
	// answers.
	linger time.Duration
}

// attemptFunc makes one attempt of the DPI checks on a connection of its
// own.
type attemptFunc func(ctx context.Context, a attempt) outcome

// residualWait is how a target waits for the residual block of the
// target checked before it at the same address.
type residualWait struct {
	recheck, limit time.Duration
}

// dpiRunner runs the DPI checks of one target.
type dpiRunner struct {
	timeout time.Duration
	// hops is the hop count to the server, and hopsMeasured is set when it
	// is the measured one rather than the maximum TTL.
	hops         int
	hopsMeasured bool
	// reachedTCP is set when the hop measurement connected to the server
	// at the default TTL.
	reachedTCP bool
	attempt    attemptFunc
	// fakesReady returns why fake packets cannot be sent, or "" when they
	// can; nil means they cannot without root.
	fakesReady func() string
	// canWatch is set when the TCP packets of the attempts are captured.
	canWatch bool
	residual residualWait
	progress targetProgress
	// baseline is the residual class of the benign ClientHello's answer
	// before any ClientHello of the target was sent, and baselineAnswer
	// that answer.
	baseline       string
	baselineAnswer outcome
	// rtt is the time a connection to the server took.
	rtt time.Duration
	// residualLeft is set when a residual block spoiled the checks.
	residualLeft bool
}

// run runs the DPI checks. prev is the URL of the target at the same
// address whose ClientHello was blocked last, if any: it may have left a
// residual block.
func (r *dpiRunner) run(ctx context.Context, prev string) DPIResult {
	res := DPIResult{Measured: true}

	// The connect is tried up to connectTries times: one lost SYN, for
	// example right after the TTL scan, must not report a reachable server
	// as unreachable.
	r.progress.phase("dpi connect")
	var conn outcome
	for range connectTries {
		var ok bool
		if conn, ok = r.once(ctx, attempt{step: stepConnect, wait: r.timeout}); !ok {
			return res
		}
		if conn.kind == outPass || conn.kind == outLocal {
			break
		}
	}
	switch {
	case conn.kind == outPass:
		r.rtt = conn.rtt
	case conn.kind == outLocal:
		res.Block = BlockResult{State: StepDone, Kind: BlockUnknown, Reason: conn.detail}
		return res
	case r.reachedTCP:
		// The hop measurement connected, so the server is not
		// unreachable.
		res.Block = BlockResult{
			State:  StepDone,
			Kind:   BlockUnknown,
			Reason: "connect failed",
		}
		return res
	default:
		res.Block = BlockResult{State: StepDone, Kind: BlockUnreachable}
		return res
	}

	if !r.takeBaseline(ctx, &res, prev) {
		return res
	}

	r.progress.phase("dpi block")
	block, ok := r.once(ctx, attempt{step: stepUnsplit, wait: r.timeout})
	if !ok {
		return res
	}
	res.Block = blockResult(block)
	if res.Block.Kind == BlockClear || res.Block.Kind == BlockUnknown {
		return res
	}
	// The block line keeps its value: its attempt ran before any residual
	// block of its own.
	if !r.residualCleared(ctx, &res, "block", "chunks") {
		return res
	}

	res.Chunks = r.chunks(ctx)
	if !r.residualCleared(ctx, &res, "chunks", "chunks") {
		return res
	}

	res.Disorder = r.disorder(ctx, res.Chunks)
	if !r.residualCleared(ctx, &res, "disorder", "disorder") {
		return res
	}

	var attempted bool
	res.Position, attempted = r.position(ctx, res.Block, conn.rtt, &res.Notes)
	if res.Position.State == StepSkipped {
		r.residualLeft = true
		skipFrom(&res, "fake")
		return res
	}
	if attempted && !r.residualCleared(ctx, &res, "position", "position") {
		return res
	}

	if !censored(res.Block) {
		return res
	}
	res.Fake, attempted = r.fake(ctx, res.Position)
	if attempted {
		r.residualCleared(ctx, &res, "fake", "fake")
	}
	return res
}

// censored reports whether the block check found the site blocked.
func censored(b BlockResult) bool {
	return b.State == StepDone &&
		(b.Kind == BlockRST || b.Kind == BlockSilent || b.Kind == BlockOther)
}

// fakesUsable returns why fake packets cannot be sent, or "" when they
// can.
func (r *dpiRunner) fakesUsable() string {
	if r.fakesReady == nil {
		return "needs root"
	}
	return r.fakesReady()
}

// takeBaseline sets the baseline the residual checks compare with, before
// any ClientHello of the target is sent. Without prev, it is the answer to
// one benign ClientHello, noted when the server does not answer it with
// TLS. With prev, the target before may have left a residual block, so the
// benign ClientHello is retried until the server answers it with TLS; if
// it does not within residual.limit, every check is skipped and
// takeBaseline returns false. It also returns false when ctx ends.
func (r *dpiRunner) takeBaseline(
	ctx context.Context,
	res *DPIResult,
	prev string,
) bool {
	if prev == "" {
		r.progress.phase("dpi baseline")
		o := r.attempt(ctx, attempt{step: stepBenign, wait: r.timeout})
		if ctx.Err() != nil {
			return false
		}
		r.baseline, r.baselineAnswer = o.residualClass(), o
		if r.baseline != answered {
			res.Notes = append(res.Notes, "benign baseline: "+r.baseline)
		}
		return true
	}

	waited, cleared := r.awaitResidual(ctx)
	if ctx.Err() != nil {
		return false
	}
	if !cleared {
		res.Block.State = StepSkipped
		skipFrom(res, "chunks")
		res.Notes = append(res.Notes, fmt.Sprintf(
			"residual block from %s (not cleared after %s)",
			prev,
			seconds(r.residual.limit),
		))
		return false
	}
	r.baseline = answered
	if waited > 0 {
		res.Notes = append(res.Notes, fmt.Sprintf(
			"waited %s for residual block from %s", seconds(waited), prev))
	}
	return true
}

// laterLines are the lines of the checks after the block check, in order.
var laterLines = []string{"chunks", "disorder", "position", "fake"}

// skipFrom marks the check of line, one of laterLines, and those after it
// as skipped. The fake check is marked only for a censored site, the only
// one it runs for.
func skipFrom(res *DPIResult, line string) {
	skipping := false
	for _, l := range laterLines {
		skipping = skipping || l == line
		if !skipping {
			continue
		}
		switch l {
		case "chunks":
			res.Chunks = ChunksResult{State: StepSkipped}
		case "disorder":
			res.Disorder = DisorderResult{State: StepSkipped}
		case "position":
			res.Position = PositionResult{State: StepSkipped}
		case "fake":
			if censored(res.Block) {
				res.Fake = FakeResult{State: StepSkipped}
			}
		}
	}
}

// residualCleared runs the residual check after the check of line. If a
// residual block is left, the results from skip on are spoiled: it marks
// them skipped, notes why and returns false. It also returns false when
// ctx ends.
func (r *dpiRunner) residualCleared(
	ctx context.Context,
	res *DPIResult,
	line, skip string,
) bool {
	if r.residualOK(ctx) {
		return true
	}
	if ctx.Err() != nil {
		return false
	}
	r.residualLeft = true
	skipFrom(res, skip)
	res.Notes = append(res.Notes, "residual block after the "+line+" check")
	return false
}

// residualOK runs the residual check: the benign ClientHello must be
// answered as it was before the target's first ClientHello. It returns
// false when it is not, or when ctx ends.
func (r *dpiRunner) residualOK(ctx context.Context) bool {
	r.progress.phase("dpi residual check")
	o := r.attempt(ctx, attempt{step: stepBenign, wait: r.timeout})
	return ctx.Err() == nil && o.residualClass() == r.baseline
}

// answered is the residual class of a benign ClientHello the server
// answers with TLS.
const answered = "answered"

// awaitResidual sends the benign ClientHello until the server answers it
// with TLS, every residual.recheck for up to residual.limit, and keeps the
// answer as baselineAnswer. It returns how long it waited when the first
// try was not answered, and whether one was.
func (r *dpiRunner) awaitResidual(
	ctx context.Context,
) (waited time.Duration, cleared bool) {
	start := time.Now()
	r.progress.phase("dpi residual check")
	for {
		o := r.attempt(ctx, attempt{step: stepBenign, wait: r.timeout})
		if ctx.Err() != nil {
			return 0, false
		}
		if o.residualClass() == answered {
			r.baselineAnswer = o
			if waited = time.Since(start); waited < r.residual.recheck {
				waited = 0
			}
			return waited, true
		}
		if time.Since(start) >= r.residual.limit {
			return 0, false
		}
		r.progress.wait("waiting for residual block", start, r.residual.limit)
		timer := time.NewTimer(r.residual.recheck)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return 0, false
		}
	}
}

// seconds formats d in whole seconds, such as "15s".
func seconds(d time.Duration) string {
	return fmt.Sprintf("%ds", int(d.Round(time.Second)/time.Second))
}

// once makes a. ok is false when ctx ended.
func (r *dpiRunner) once(ctx context.Context, a attempt) (o outcome, ok bool) {
	o = r.attempt(ctx, a)
	return o, ctx.Err() == nil
}

// blockResult classifies the outcome of the block check.
func blockResult(o outcome) BlockResult {
	b := BlockResult{State: StepDone}
	switch o.kind {
	case outPass:
		b.Kind = BlockClear
	case outRST:
		b.Kind = BlockRST
	case outDrop:
		b.Kind = BlockSilent
	case outLocal:
		b.Kind, b.Reason = BlockUnknown, o.detail
	default:
		b.Kind, b.Reason = BlockOther, o.detail
	}
	return b
}

// chunks sends the ClientHello in ever smaller chunks, until they get
// through.
func (r *dpiRunner) chunks(ctx context.Context) ChunksResult {
	c := ChunksResult{State: StepDone, Reassembled: true}
loop:
	for _, n := range chunkSizes {
		r.progress.phase(fmt.Sprintf("dpi chunks %d bytes", n))
		o, ok := r.once(ctx, attempt{step: stepChunks, size: n, wait: r.timeout})
		if !ok {
			break
		}
		switch o.kind {
		case outPass:
			c.PassAt = n
			c.Reassembled = n != chunkSizes[0]
			break loop
		case outLocal:
			c.Reason = o.detail
			break loop
		default:
			c.SmallestBlocked = n
		}
	}
	if c.SmallestBlocked == 0 {
		c.SmallestBlocked = chunkSizes[0]
	}
	return c
}

// disorder sends the ClientHello in the smallest chunks that were blocked
// in order, or the largest if none was, with disorder. The disordered
// chunks reach the server only when retransmitted, so it waits twice the
// timeout.
func (r *dpiRunner) disorder(ctx context.Context, c ChunksResult) DisorderResult {
	size := c.SmallestBlocked
	r.progress.phase(fmt.Sprintf("dpi disorder %d bytes", size))
	o, ok := r.once(ctx, attempt{step: stepDisorder, size: size, wait: 2 * r.timeout})
	if !ok {
		return DisorderResult{}
	}
	d := DisorderResult{State: StepDone, Size: size}
	switch o.kind {
	case outPass:
		d.Pass = true
	case outLocal:
		d.Reason = o.detail
	}
	return d
}
