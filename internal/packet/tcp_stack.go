package packet

import (
	"net"
	"time"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/cache"
	"github.com/xvzc/spoofdpi/internal/capture"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/netutil"
)

// seqEntryTTL is how long the sequence numbers learned from a SYN/ACK are
// kept when no connection asks for them.
const seqEntryTTL = 5 * time.Second

// TCPStack is what fake TCP packets are sent with: a SYN/ACK sniffer that
// learns hop counts and sequence numbers, and a writer that injects
// crafted packets, sharing one capture handle.
type TCPStack struct {
	Sniffer *TCPSniffer
	Writer  *TCPWriter
	Seqs    *SeqTracker
}

// OpenTCPStack opens one capture handle on iface, shared by a SYN/ACK
// sniffer that records hop counts in hopCache and sequence numbers in Seqs,
// and a writer that injects packets to gatewayMAC, and starts the sniffer.
// The handle stays open for the life of the process: the sniffer reads it
// until then.
func OpenTCPStack(
	logger zerolog.Logger,
	iface *net.Interface,
	gatewayMAC net.HardwareAddr,
	hopCache cache.Cache[netutil.IPKey, HopEntry],
	rc *config.RuntimeConfig,
) (*TCPStack, error) {
	handle, err := capture.NewHandle(iface)
	if err != nil {
		return nil, err
	}
	seqs := NewSeqTracker(seqEntryTTL)
	sniffer := NewTCPSniffer(logger, handle, hopCache, seqs, rc)
	writer := NewTCPWriter(logger, handle, iface, gatewayMAC)
	sniffer.StartCapturing()
	return &TCPStack{Sniffer: sniffer, Writer: writer, Seqs: seqs}, nil
}
