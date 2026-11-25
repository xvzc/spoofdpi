package packet

import (
	"errors"
	"net"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/packetio/capture"
)

// UDPStack is what fake UDP packets are sent with: a sniffer that learns
// hop counts, and a writer that sends crafted packets through its
// senders.
type UDPStack struct {
	Sniffer *UDPSniffer
	Writer  *UDPWriter
}

// OpenUDPStack opens a capture handle on iface for a sniffer that records
// hop counts in hops, starts the sniffer, which logs under the trace ID
// runID, and makes a writer that sends
// packets through senders. It fails, closing the handle, if the sniffer
// cannot start. The handle stays open for the life of the process: the
// sniffer reads it until then.
//
// If iface has a link type the capture filter does not support, the
// handle is closed and the stack has a nil Sniffer: no hop counts are
// learned there, and fake packets use the default hop count.
func OpenUDPStack(
	runID string,
	logger zerolog.Logger,
	iface *net.Interface,
	senders Senders,
	hops *HopStore,
) (*UDPStack, error) {
	handle, err := newCaptureHandle(iface)
	if err != nil {
		return nil, err
	}
	sniffer := NewUDPSniffer(runID, logger, handle, hops)
	writer := NewUDPWriter(logger, senders)
	if err := sniffer.StartCapturing(); err != nil {
		handle.Close()
		if errors.Is(err, capture.ErrUnsupportedLinkType) {
			logger.Warn().
				Str("interface", iface.Name).
				Err(err).
				Msg("hop counts are not learned on this interface; " +
					"fake packets use hop-count-default")
			return &UDPStack{Writer: writer}, nil
		}
		return nil, err
	}
	return &UDPStack{Sniffer: sniffer, Writer: writer}, nil
}
