package probe

import (
	"context"
	"strconv"
	"strings"
	"time"
)

// alertNames are the names of the TLS alerts a server commonly sends a
// ClientHello it does not accept.
var alertNames = map[int]string{
	10:  "unexpected_message",
	20:  "bad_record_mac",
	22:  "record_overflow",
	40:  "handshake_failure",
	47:  "illegal_parameter",
	50:  "decode_error",
	70:  "protocol_version",
	80:  "internal_error",
	109: "missing_extension",
	110: "unsupported_extension",
	112: "unrecognized_name",
	120: "no_application_protocol",
}

// server runs the server check of a target whose DPI checks found res,
// if it applies: it sends fakes with restoredTTL before a ClientHello the
// DPI lets through, and checks that the server answers that ClientHello
// with a ServerHello for it, as it does without the fake. It searches for
// the seq and ack offsets whose fakes the server drops, then tries the
// bad_md5 fake. A residual block after it is noted in res.
//
// For a clear site, that ClientHello is the site's own. For a blocked one,
// it is the one for benignSNI, which works only when the server answers it
// with a ServerHello: a server that rejects names it does not host would
// reject the fake's name too, so taking the fake would look the same as
// dropping it.
func (r *dpiRunner) server(ctx context.Context, res *DPIResult) ServerResult {
	if !serverChecked(res.Block) || ctx.Err() != nil {
		return ServerResult{}
	}
	if r.residualLeft {
		return ServerResult{Measured: true, State: StepSkipped}
	}
	s := ServerResult{
		Measured: true, State: StepDone, BadSNI: badSNIValue(r.baselineAnswer),
	}
	step := stepServerFakeHost
	if res.Block.State != StepDone || res.Block.Kind != BlockClear {
		switch r.baselineAnswer.kind {
		case outPass:
			step = stepServerFake
		case outLocal:
			// The baseline failed on this host, which says nothing about
			// the server.
			s.Reason = r.baselineAnswer.detail
			return s
		default:
			s.Reason = "server rejects unknown SNI"
			return s
		}
	}
	r.progress.phase("server preparing fake packets")
	if reason := r.fakesUsable(); reason != "" {
		s.Reason = reason
		return s
	}

	sr := serverRunner{dpiRunner: r, step: step, linger: positionWait(r.rtt, r.timeout)}
	var ok bool
	if s.SeqOffset, ok = sr.offsets(ctx, seqVariant); !ok {
		return ServerResult{}
	}
	if s.AckOffset, ok = sr.offsets(ctx, ackVariant); !ok {
		return ServerResult{}
	}
	if s.BadMD5, ok = sr.variant(ctx, badMD5Variant); !ok {
		return ServerResult{}
	}
	if !r.residualOK(ctx) {
		res.Notes = append(res.Notes, "residual block after the server check")
		return ServerResult{Measured: true, State: StepSkipped}
	}
	return s
}

// serverChecked reports whether the server check runs after the block
// check found b: for a site that is clear or censored.
func serverChecked(b BlockResult) bool {
	return b.State == StepDone && b.Kind != BlockUnreachable && b.Kind != BlockUnknown
}

// badSNIValue returns the value of the bad_sni line for the answer to the
// benign ClientHello.
func badSNIValue(o outcome) string {
	switch {
	case o.kind == outLocal:
		return "unknown (" + o.detail + ")"
	case o.kind == outPass:
		return "answers"
	case o.kind == outRST:
		return "reset"
	case o.kind == outDrop:
		return "silent"
	case o.serverReplied:
		alert := strings.TrimPrefix(o.detail, "TLS ")
		code, err := strconv.Atoi(strings.TrimPrefix(alert, "alert "))
		if name, ok := alertNames[code]; ok && err == nil {
			return alert + " (" + name + ")"
		}
		return alert
	}
	return o.detail
}

// serverRunner makes the attempts of the server check of a target.
type serverRunner struct {
	*dpiRunner
	// step is stepServerFake or stepServerFakeHost, and linger the
	// attempts' linger.
	step   dpiStep
	linger time.Duration
}

// variant makes the attempt of the fake v. ok is false when ctx ended.
func (sr serverRunner) variant(
	ctx context.Context,
	v fakeVariant,
) (res ServerVariantResult, ok bool) {
	sr.progress.phase("server " + v.name)
	o, ok := sr.once(ctx, attempt{
		step: sr.step, variant: v, wait: sr.timeout, linger: sr.linger,
	})
	if !ok {
		return ServerVariantResult{}, false
	}
	return serverVariantResult(o), true
}

// offsets searches for the smallest power of two m from which on the
// server drops the fakes variant(m). ok is false when ctx ended.
func (sr serverRunner) offsets(
	ctx context.Context,
	variant func(m int64) fakeVariant,
) (res ServerOffsetResult, ok bool) {
	s, ok := searchOffset(func(m int64) (searchPoint, bool) {
		v, ok := sr.variant(ctx, variant(m))
		return serverPoint(v), ok
	})
	if !ok {
		return ServerOffsetResult{}, false
	}
	switch {
	case s.unstable:
		return ServerOffsetResult{State: StepUnstable}, true
	case s.reason != "":
		return ServerOffsetResult{State: StepDone, Reason: s.reason}, true
	}
	return ServerOffsetResult{
		State:     StepDone,
		DropsFrom: s.firstAfter,
		LastBreak: s.lastBefore,
		Break:     s.beforeDetail,
	}, true
}

// serverPoint is the point of an offset search for the result of its
// fake: a fake that breaks the connection is before the boundary.
func serverPoint(v ServerVariantResult) searchPoint {
	switch {
	case v.Reason != "":
		return searchPoint{side: sideUnknown, detail: v.Reason}
	case v.Drops:
		return searchPoint{side: sideAfter}
	}
	return searchPoint{side: sideBefore, detail: v.Break}
}

// serverVariantResult classifies the outcome of a fake of the server
// check.
func serverVariantResult(o outcome) ServerVariantResult {
	if o.kind == outLocal {
		return ServerVariantResult{State: StepDone, Reason: o.detail}
	}
	if b := serverBreak(o); b != "" {
		return ServerVariantResult{State: StepDone, Break: b}
	}
	return ServerVariantResult{State: StepDone, Drops: true}
}

// serverBreak returns how the connection of a try of the server check
// went otherwise than without the fake, or "" when the server answered the
// real ClientHello with a ServerHello, as it does without the fake.
func serverBreak(o outcome) string {
	switch {
	case o.answeredFake:
		return "bad sni"
	case o.kind == outPass:
		return ""
	case o.kind == outRST:
		return "reset"
	case o.kind == outDrop:
		return "timeout"
	case o.serverReplied:
		return strings.TrimPrefix(o.detail, "TLS ")
	}
	return o.detail
}
