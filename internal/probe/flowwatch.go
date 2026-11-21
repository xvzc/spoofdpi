package probe

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/xvzc/spoofdpi/internal/capture"
)

// flowKey names a TCP connection to a probed server.
type flowKey struct {
	server    netip.AddrPort
	localPort uint16
}

// flowSegment is a captured segment of a watched connection.
type flowSegment struct {
	// out is set for a segment this host sent to the server.
	out bool
	capture.TCPSegment
}

// verdict is what a check of the captured segments of a connection
// found.
type verdict int

const (
	// undecided: the segments looked for have not been captured yet.
	undecided verdict = iota
	// matched: they have.
	matched
	// failed: segments were captured that rule them out.
	failed
)

// flowWatch reads TCP segments from a packet source and keeps those of the
// connections it is told to watch, in both directions.
type flowWatch struct {
	src     packetSource
	stopped atomic.Bool
	done    chan struct{}

	mu    sync.Mutex
	flows map[flowKey][]flowSegment
	// added is closed, and replaced, when a segment is kept.
	added chan struct{}
}

// newFlowWatch starts reading from src. Close stops it and closes src.
func newFlowWatch(src packetSource) *flowWatch {
	w := &flowWatch{
		src:   src,
		done:  make(chan struct{}),
		flows: map[flowKey][]flowSegment{},
		added: make(chan struct{}),
	}
	go w.read()
	return w
}

func (w *flowWatch) read() {
	defer close(w.done)
	linkType := w.src.LinkType()
	for !w.stopped.Load() {
		data, _, err := w.src.ReadPacketData()
		if err != nil {
			if capture.IsReadTimeout(err) {
				continue
			}
			// The checks that need the capture then find nothing.
			return
		}
		seg, ok := capture.ParseTCPSegment(
			gopacket.NewPacket(data, linkType, gopacket.Default),
		)
		if !ok {
			continue
		}
		w.keep(seg)
	}
}

// keep keeps seg if it belongs to a watched connection.
func (w *flowWatch) keep(seg capture.TCPSegment) {
	src, srcOK := netip.AddrFromSlice(seg.Src.To4())
	dst, dstOK := netip.AddrFromSlice(seg.Dst.To4())
	if !srcOK || !dstOK {
		return
	}
	in := flowKey{netip.AddrPortFrom(src, seg.SrcPort), seg.DstPort}
	out := flowKey{netip.AddrPortFrom(dst, seg.DstPort), seg.SrcPort}

	w.mu.Lock()
	defer w.mu.Unlock()
	key, isOut := in, false
	if _, ok := w.flows[in]; !ok {
		if _, ok := w.flows[out]; !ok {
			return
		}
		key, isOut = out, true
	}
	w.flows[key] = append(w.flows[key], flowSegment{out: isOut, TCPSegment: seg})
	close(w.added)
	w.added = make(chan struct{})
}

// track starts keeping the segments of flow, and returns the function that
// stops it and forgets them.
func (w *flowWatch) track(flow flowKey) (untrack func()) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.flows[flow] = nil
	return func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		delete(w.flows, flow)
	}
}

// await waits up to wait until check, given the segments of flow kept so
// far, decides. It returns undecided if check does not decide in time, or
// ctx ends.
func (w *flowWatch) await(
	ctx context.Context,
	flow flowKey,
	wait time.Duration,
	check func(segs []flowSegment) verdict,
) verdict {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		w.mu.Lock()
		v := check(w.flows[flow])
		added := w.added
		w.mu.Unlock()
		if v != undecided {
			return v
		}

		select {
		case <-added:
		case <-timer.C:
			return undecided
		case <-ctx.Done():
			return undecided
		}
	}
}

// Close stops reading and closes the packet source, as learner.Close
// does.
func (w *flowWatch) Close() {
	w.stopped.Store(true)
	<-w.done
	w.src.Close()
}
