package packet

import (
	"errors"
	"net"
	"time"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/capture"
)

// seqEntryTTL is how long the sequence numbers learned from a SYN/ACK are
// kept when no connection asks for them.
const seqEntryTTL = 5 * time.Second

// newCaptureHandle opens the capture handles of the stacks; tests replace
// it.
var newCaptureHandle = capture.NewHandle

// TCPStack is what fake TCP packets are sent with: a SYN/ACK sniffer that
// learns hop counts and sequence numbers, and a writer that sends crafted
// packets through its senders.
type TCPStack struct {
	Sniffer *TCPSniffer
	Writer  *TCPWriter
	Seqs    *SeqTracker
}

// OpenTCPStack opens a capture handle on iface for a SYN/ACK sniffer that
// records hop counts in hops and sequence numbers in Seqs, starts the
// sniffer, and makes a writer that sends packets through senders. It
// fails, closing the handle, if the sniffer cannot start. The handle stays
// open for the life of the process: the sniffer reads it until then.
//
// If iface has a link type the capture filter does not support, the
// handle is closed and the stack has a nil Sniffer and Seqs: nothing is
// learned there, and fake packets use the default hop count and random
// sequence numbers.
func OpenTCPStack(
	logger zerolog.Logger,
	iface *net.Interface,
	senders Senders,
	hops *HopStore,
) (*TCPStack, error) {
	handle, err := newCaptureHandle(iface)
	if err != nil {
		return nil, err
	}
	seqs := NewSeqTracker(seqEntryTTL)
	sniffer := NewTCPSniffer(logger, handle, hops, seqs)
	writer := NewTCPWriter(logger, senders)
	if err := sniffer.StartCapturing(); err != nil {
		handle.Close()
		if errors.Is(err, capture.ErrUnsupportedLinkType) {
			logger.Warn().
				Str("interface", iface.Name).
				Err(err).
				Msg("hop counts and sequence numbers are not learned on this interface; " +
					"fake packets use hop-count-default and random sequence numbers")
			return &TCPStack{Writer: writer}, nil
		}
		return nil, err
	}
	return &TCPStack{Sniffer: sniffer, Writer: writer, Seqs: seqs}, nil
}
