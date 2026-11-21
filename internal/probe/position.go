package probe

import (
	"context"
	"fmt"
	"time"
)

// The bounds of the wait for an answer in the position check.
const (
	minPositionWait = 500 * time.Millisecond
	positionWaitPad = 200 * time.Millisecond
)

// positionWait is how long a position attempt waits for an answer: four
// round trips plus some slack, but at least minPositionWait and at most
// timeout.
func positionWait(rtt, timeout time.Duration) time.Duration {
	return min(max(4*rtt+positionWaitPad, minPositionWait), timeout)
}

// position finds the hop the DPI acts at, by how it blocks. rtt is the
// round trip time of a connection. A note is added to notes when a
// residual block cuts the check short. attempted is set when it sent
// ClientHellos.
func (r *dpiRunner) position(
	ctx context.Context,
	block BlockResult,
	rtt time.Duration,
	notes *[]string,
) (p PositionResult, attempted bool) {
	wait := positionWait(rtt, r.timeout)
	switch {
	case block.Kind == BlockRST:
		p = r.rstPosition(ctx, wait)
	case block.Kind == BlockSilent && !r.canWatch:
		return PositionResult{State: StepDone, Reason: "needs root"}, false
	case block.Kind == BlockSilent:
		p = r.silentPosition(ctx, wait)
	default:
		return PositionResult{
			State: StepDone, Reason: "block is neither RST nor silent",
		}, false
	}
	if p.State == StepSkipped {
		*notes = append(*notes, "residual block during the position check")
	}
	return p, r.hops > 0
}

// rstPosition sends the ClientHello with TTL 1 up to the hop count: the
// DPI is at the first TTL that is reset.
func (r *dpiRunner) rstPosition(
	ctx context.Context,
	wait time.Duration,
) PositionResult {
	for ttl := 1; ttl <= r.hops; ttl++ {
		r.progress.phase(fmt.Sprintf("dpi position TTL %d", ttl))
		o, ok := r.once(ctx, attempt{step: stepPositionRST, ttl: ttl, wait: wait})
		switch {
		case !ok:
			return PositionResult{}
		case o.connectFailed:
			return PositionResult{State: StepSkipped}
		case o.kind == outLocal:
			return PositionResult{State: StepDone, Reason: o.detail}
		case o.kind == outRST:
			return PositionResult{State: StepDone, Hop: ttl}
		}
	}
	return PositionResult{State: StepDone}
}

// silentPosition sends the ClientHello with TTL 1 up to the hop count,
// then a byte past it that reaches the server. A TTL up to the hop count
// dies at a router at the latest, so the server never gets the
// ClientHello. Until the ClientHello reaches the DPI, the server
// acknowledges the byte with a duplicate ACK; once it does, the DPI drops
// the connection. The DPI is at the first TTL that gets no duplicate ACK.
// An attempt that failed on this host, such as one whose packets did not
// leave with the TTL set, ends the check with its reason.
func (r *dpiRunner) silentPosition(
	ctx context.Context,
	wait time.Duration,
) PositionResult {
	for ttl := 1; ttl <= r.hops; ttl++ {
		r.progress.phase(fmt.Sprintf("dpi position TTL %d", ttl))
		o, ok := r.once(ctx, attempt{step: stepPositionSilent, ttl: ttl, wait: wait})
		switch {
		case !ok:
			return PositionResult{}
		case o.connectFailed:
			return PositionResult{State: StepSkipped}
		case o.kind == outPass:
			continue
		case o.kind != outDrop:
			return PositionResult{State: StepDone, Reason: o.detail}
		case ttl == 1:
			// No duplicate ACK even when the ClientHello dies at the
			// first hop: the server or the path does not answer the
			// byte, so the check cannot tell where the DPI is.
			return PositionResult{State: StepDone, Reason: "no dup ACK"}
		}
		return PositionResult{State: StepDone, Hop: ttl}
	}
	return PositionResult{State: StepDone, Reason: "per-packet drop"}
}
