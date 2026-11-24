package packet

import (
	"net"
	"time"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/capture"
)

// seqEntryTTL is how long the sequence numbers learned from a SYN/ACK are
// kept when no connection asks for them.
const seqEntryTTL = 5 * time.Second

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
func OpenTCPStack(
	logger zerolog.Logger,
	iface *net.Interface,
	senders Senders,
	hops *HopStore,
) (*TCPStack, error) {
	handle, err := capture.NewHandle(iface)
	if err != nil {
		return nil, err
	}
	seqs := NewSeqTracker(seqEntryTTL)
	sniffer := NewTCPSniffer(logger, handle, hops, seqs)
	writer := NewTCPWriter(logger, senders)
	if err := sniffer.StartCapturing(); err != nil {
		handle.Close()
		return nil, err
	}
	return &TCPStack{Sniffer: sniffer, Writer: writer, Seqs: seqs}, nil
}
