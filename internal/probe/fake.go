package probe

import (
	"context"
	"fmt"

	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/proto"
)

// fakeVariant is a way of crafting the fake ClientHello, as spoofdpi's
// fake-seq-offset, fake-ack-offset and fake-bad-md5sig options do.
type fakeVariant struct {
	name                 string
	seqOffset, ackOffset int64
	badMD5               bool
}

// The fakes of the fake check besides those of the offset searches. The
// ttl variant, with the connection's own sequence numbers, comes first:
// the others are tried only when it gets through. The server check tries
// bad_md5, not ttl.
var (
	ttlVariant    = fakeVariant{name: "ttl"}
	badMD5Variant = fakeVariant{name: "bad_md5", badMD5: true}
)

// seqVariant is the fake of the offset searches with fake-seq-offset -m.
func seqVariant(m int64) fakeVariant {
	return fakeVariant{name: fmt.Sprintf("seq_offset %d", -m), seqOffset: -m}
}

// ackVariant is the fake of the offset searches with fake-ack-offset -m.
func ackVariant(m int64) fakeVariant {
	return fakeVariant{name: fmt.Sprintf("ack_offset %d", -m), ackOffset: -m}
}

// fakeOpts sends the ClientHello in one write, after one fake ClientHello
// crafted as v says: spoofdpi's default fake, for www.google.com.
func fakeOpts(v fakeVariant) *config.HTTPSOptions {
	return &config.HTTPSOptions{
		SplitMode:     config.HTTPSSplitModeNone,
		FakePreflight: 1,
		FakePacket:    proto.NewFakeTLSMessage([]byte(config.FakeClientHello)),
		FakeSeqOffset: v.seqOffset,
		FakeAckOffset: v.ackOffset,
		FakeBadMD5Sig: v.badMD5,
		// The fake's sequence numbers are checked against the capture, so
		// the wait can be longer than spoofdpi's.
		SynAckTimeout: defaultLearnWait,
	}
}

// fake runs the fake check of a censored site, given the position check's
// result. attempted is set when it sent ClientHellos.
func (r *dpiRunner) fake(
	ctx context.Context,
	pos PositionResult,
) (f FakeResult, attempted bool) {
	ttl, reason := r.fakeTTL(pos)
	if reason == "" {
		r.progress.phase("preparing fake packets")
		reason = r.fakesUsable()
	}
	if reason != "" {
		return FakeResult{State: StepDone, Reason: reason}, false
	}

	f = FakeResult{State: StepDone}
	var ok bool
	if f.TTL, ok = r.fakeVariant(ctx, ttl, ttlVariant); !ok {
		return FakeResult{}, true
	}
	// The other fakes are worth trying only if a fake that differs from
	// the real ClientHello in its TTL alone fools the DPI.
	if !f.TTL.Pass {
		return f, true
	}
	if f.SeqOffset, ok = r.fakeOffsets(ctx, ttl, seqVariant); !ok {
		return FakeResult{}, true
	}
	if f.AckOffset, ok = r.fakeOffsets(ctx, ttl, ackVariant); !ok {
		return FakeResult{}, true
	}
	if f.BadMD5, ok = r.fakeVariant(ctx, ttl, badMD5Variant); !ok {
		return FakeResult{}, true
	}
	return f, true
}

// fakeVariant makes the attempt of the fake v, with TTL ttl. ok is false
// when ctx ended.
func (r *dpiRunner) fakeVariant(
	ctx context.Context,
	ttl int,
	v fakeVariant,
) (res FakeVariantResult, ok bool) {
	r.progress.phase("dpi fake " + v.name)
	o, ok := r.once(ctx, attempt{step: stepFake, ttl: ttl, variant: v, wait: r.timeout})
	if !ok {
		return FakeVariantResult{}, false
	}
	return fakeVariantResult(o), true
}

// fakeOffsets searches for the largest power of two m up to which the
// fakes variant(m), with TTL ttl, fool the DPI. ok is false when ctx
// ended.
func (r *dpiRunner) fakeOffsets(
	ctx context.Context,
	ttl int,
	variant func(m int64) fakeVariant,
) (res FakeOffsetResult, ok bool) {
	s, ok := searchOffset(func(m int64) (searchPoint, bool) {
		v, ok := r.fakeVariant(ctx, ttl, variant(m))
		return fakePoint(v), ok
	})
	if !ok {
		return FakeOffsetResult{}, false
	}
	switch {
	case s.unstable:
		return FakeOffsetResult{State: StepUnstable}, true
	case s.reason != "":
		return FakeOffsetResult{State: StepDone, Reason: s.reason}, true
	}
	return FakeOffsetResult{
		State: StepDone, MaxPass: s.lastBefore, MinFail: s.firstAfter,
	}, true
}

// fakePoint is the point of an offset search for the result of its fake:
// a fake that fools the DPI is before the boundary.
func fakePoint(v FakeVariantResult) searchPoint {
	switch {
	case v.Reason != "":
		return searchPoint{side: sideUnknown, detail: v.Reason}
	case v.Pass:
		return searchPoint{side: sideBefore}
	}
	return searchPoint{side: sideAfter}
}

// fakeTTL returns the TTL of the fakes of the fake check: the hop of the
// DPI, or else the hop count minus 1, at least 1, as spoofdpi's. Both die
// before the server only when the hop count was measured, since the
// position check then tries no TTL above it. reason says why there is
// none.
func (r *dpiRunner) fakeTTL(pos PositionResult) (ttl int, reason string) {
	switch {
	case !r.hopsMeasured:
		return 0, "hop count unknown"
	case pos.State == StepDone && pos.Hop > 0:
		return pos.Hop, ""
	case r.hops == 0:
		return 0, "server on local link"
	}
	return max(r.hops-1, 1), ""
}

// fakeVariantResult classifies the outcome of a fake of the fake check. A
// server that answered the fake got it although its TTL should have
// stopped it, which says nothing about the DPI.
func fakeVariantResult(o outcome) FakeVariantResult {
	switch {
	case o.answeredFake:
		return FakeVariantResult{State: StepDone, Reason: "fake reached server"}
	case o.kind == outPass:
		return FakeVariantResult{State: StepDone, Pass: true}
	case o.kind == outLocal:
		return FakeVariantResult{State: StepDone, Reason: o.detail}
	}
	return FakeVariantResult{State: StepDone}
}
