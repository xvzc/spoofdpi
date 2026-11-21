package probe

import (
	"strings"
	"time"
)

// progressEvent is a change in what the measurement of one target is
// doing.
type progressEvent struct {
	// target is the index of the target in the --url order.
	target int
	// phase is what the target is doing, such as "hops" or
	// "dpi chunks 20 bytes".
	phase string
	// waitStart and waitLimit are set while the target waits, for up to
	// waitLimit since waitStart.
	waitStart time.Time
	waitLimit time.Duration
	// done is set when the target is finished.
	done bool
}

// progressFunc receives the progress events of all targets, from
// concurrent goroutines.
type progressFunc func(progressEvent)

// targetProgress reports the progress of one target. The zero value
// reports nothing.
type targetProgress struct {
	report progressFunc
	target int
}

// phase reports that the target is now doing what text says.
func (p targetProgress) phase(text string) {
	if p.report != nil {
		p.report(progressEvent{target: p.target, phase: text})
	}
}

// wait reports that the target waits, as text says, for up to limit since
// start.
func (p targetProgress) wait(text string, start time.Time, limit time.Duration) {
	if p.report != nil {
		p.report(progressEvent{
			target: p.target, phase: text, waitStart: start, waitLimit: limit,
		})
	}
}

// done reports that the target is finished.
func (p targetProgress) done() {
	if p.report != nil {
		p.report(progressEvent{target: p.target, done: true})
	}
}

// progressStage is a phase of the measurement of a target, with the
// fraction of the target's work that is done when the phase begins.
type progressStage struct {
	// prefix matches the start of the phase text of the events.
	prefix string
	start  float64
}

// progressStages lists the phases in the order a target goes through
// them. The shares are a rough guess of how long each takes, with the
// long phases (chunks, fake and server) taking the most; they only make
// the progress bar move, not predict the time left. A target that skips
// a phase jumps ahead to the next one it reports, and a finished target
// is at 1. Phases not listed, such as the residual check and waiting for
// a residual block, leave the fraction where it is.
var progressStages = []progressStage{
	{"resolving", 0},
	{"hops", 0.02},
	{"queued for checks", 0.08},
	{"quic", 0.10},
	{"dpi connect", 0.14},
	{"dpi baseline", 0.14},
	{"dpi block", 0.17},
	{"dpi chunks", 0.22},
	{"dpi disorder", 0.45},
	{"dpi position", 0.52},
	{"preparing fake packets", 0.58},
	{"dpi fake", 0.58},
	{"server", 0.80},
}

// phaseFraction returns the fraction of the work of a target that is
// done when it begins the phase, and false when the phase is not one of
// the stages.
func phaseFraction(phase string) (float64, bool) {
	for _, s := range progressStages {
		if strings.HasPrefix(phase, s.prefix) {
			return s.start, true
		}
	}
	return 0, false
}

// activity is what a target is doing, as the status line names it. The
// order of the values is the order the words are shown in.
type activity int

const (
	activityNone activity = iota - 1
	activityResolving
	activityHops
	activityQUIC
	activityDPI
	activityFake
	activityServer
	activityResidualWait
	activityCount
)

// activityWords are the words the status line shows, per activity.
var activityWords = [activityCount]string{
	activityResolving:    "resolving",
	activityHops:         "measuring hops",
	activityQUIC:         "checking QUIC",
	activityDPI:          "checking DPI",
	activityFake:         "testing fake packets",
	activityServer:       "checking server",
	activityResidualWait: "waiting for residual block",
}

// phaseActivity returns the activity a phase belongs to, and false when
// the phase is none of them.
func phaseActivity(phase string) (activity, bool) {
	switch {
	case phase == "resolving":
		return activityResolving, true
	case phase == "hops":
		return activityHops, true
	case phase == "quic":
		return activityQUIC, true
	case phase == "waiting for residual block":
		return activityResidualWait, true
	case phase == "preparing fake packets":
		return activityFake, true
	case strings.HasPrefix(phase, "dpi fake"):
		return activityFake, true
	case strings.HasPrefix(phase, "dpi"):
		return activityDPI, true
	case phase == "queued for checks":
		// The QUIC check comes next.
		return activityQUIC, true
	case strings.HasPrefix(phase, "server"):
		return activityServer, true
	}
	return activityNone, false
}
