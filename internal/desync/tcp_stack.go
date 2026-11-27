package desync

import (
	"context"
	"net"
	"time"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/packetio/capture"
)

// seqEntryTTL is how long the sequence numbers learned from a SYN/ACK are
// kept when no connection asks for them.
const seqEntryTTL = 5 * time.Second

// newCaptureHandle opens the capture handles of the stacks; tests replace
// it.
var newCaptureHandle = capture.NewHandle

// EgressIface is an interface that the traffic of the address families in
// Fams leaves the host through.
type EgressIface struct {
	Iface net.Interface
	Fams  netutil.FamilySet
}

// SeqSource gives the sequence numbers learned from the SYN/ACKs of TCP
// connections.
type SeqSource interface {
	// LearnsSeq reports whether sequence numbers are learned for the
	// connections to remote. Waiting for any other would always time out.
	LearnsSeq(remote net.IP) bool
	// Wait returns the sequence numbers learned for key, as
	// SeqTracker.Wait does.
	Wait(ctx context.Context, key netutil.NATKey, timeout time.Duration) (SeqAck, bool)
}

var _ SeqSource = (*TCPStack)(nil)

// TCPStack is what fake TCP packets are sent with: SYN/ACK sniffers that
// learn hop counts and sequence numbers, and a writer that sends crafted
// packets through its senders.
type TCPStack struct {
	// Sniffers are the sniffers of the interfaces whose capture handles
	// work, one per interface.
	Sniffers []*TCPSniffer
	Writer   *TCPWriter
	// Seqs holds the sequence numbers the sniffers learn, or is nil when
	// no sniffer runs.
	Seqs *SeqTracker

	// learns is the set of the address families the sniffers capture.
	learns netutil.FamilySet
}

// OpenTCPStack opens a capture handle on each of ifaces for a SYN/ACK
// sniffer of the families of that interface, which records hop counts in
// hops and sequence numbers in Seqs, starts the sniffers, which log under
// the trace ID runID, and makes a writer that sends packets through
// senders. Each interface must appear once in ifaces. The handles stay
// open for the life of the process: the sniffers read them until then.
//
// A family whose packets cannot be captured is not learned: its fake
// packets use the default hop count and random sequence numbers. Only
// IPv4 must be captured:
//
//   - On a link type the capture filter does not support, the handle is
//     closed with a warning, whatever its families.
//   - Any other failure to open or start the handle of an interface
//     without IPv4 is a warning; a handle that opened is closed.
//   - If the sniffer of an interface of both families does not start, the
//     sniffer of IPv4 alone is started on it, with a warning.
//
// The other handles are kept. OpenTCPStack fails if the handle of IPv4
// cannot be opened or its sniffer cannot start, with an error that names
// the interface; the sniffers already started keep their handles, as the
// error is meant to end the process.
func OpenTCPStack(
	runID string,
	logger zerolog.Logger,
	ifaces []EgressIface,
	senders Senders,
	hops *HopStore,
) (*TCPStack, error) {
	seqs := NewSeqTracker(seqEntryTTL)
	stack := &TCPStack{Writer: NewTCPWriter(logger, senders)}
	newSniffer := func(h capture.Handle, fams netutil.FamilySet) *TCPSniffer {
		return NewTCPSniffer(runID, logger, h, fams, hops, seqs)
	}
	for _, e := range ifaces {
		sniffer, learns, err := startSniffer(logger, e, newSniffer, tcpCaptureWarnings)
		if err != nil {
			return nil, err
		}
		if sniffer != nil {
			stack.Sniffers = append(stack.Sniffers, sniffer)
			stack.learns |= learns
		}
	}
	if len(stack.Sniffers) > 0 {
		stack.Seqs = seqs
	}
	return stack, nil
}

// tcpCaptureWarnings are the warnings of the families that a TCP stack
// does not capture.
var tcpCaptureWarnings = captureWarnings{
	none: "hop counts and sequence numbers are not learned on this interface; " +
		"fake packets use hop-count-default and random sequence numbers",
	ipv6: "hop counts and sequence numbers are not learned for IPv6 on this " +
		"interface; IPv6 fake packets use hop-count-default and random " +
		"sequence numbers",
}

// LearnsSeq reports whether a sniffer of s captures the SYN/ACKs of
// remote's address family. An IPv4-mapped IPv6 address is IPv4.
func (s *TCPStack) LearnsSeq(remote net.IP) bool {
	switch {
	case remote.To4() != nil:
		return s.learns.Has(netutil.FamilyV4)
	case remote.To16() != nil:
		return s.learns.Has(netutil.FamilyV6)
	default:
		return false
	}
}

// Wait returns the sequence numbers the sniffers learned for key, as
// SeqTracker.Wait does. ok is false at once when no sniffer runs.
func (s *TCPStack) Wait(
	ctx context.Context,
	key netutil.NATKey,
	timeout time.Duration,
) (seq SeqAck, ok bool) {
	if s.Seqs == nil {
		return SeqAck{}, false
	}
	return s.Seqs.Wait(ctx, key, timeout)
}
