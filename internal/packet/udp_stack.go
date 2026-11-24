package packet

import (
	"net"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/capture"
)

// UDPStack is what fake UDP packets are sent with: a sniffer that learns
// hop counts, and a writer that sends crafted packets through its
// senders.
type UDPStack struct {
	Sniffer *UDPSniffer
	Writer  *UDPWriter
}

// OpenUDPStack opens a capture handle on iface for a sniffer that records
// hop counts in hops, starts the sniffer, and makes a writer that sends
// packets through senders. It fails, closing the handle, if the sniffer
// cannot start. The handle stays open for the life of the process: the
// sniffer reads it until then.
func OpenUDPStack(
	logger zerolog.Logger,
	iface *net.Interface,
	senders Senders,
	hops *HopStore,
) (*UDPStack, error) {
	handle, err := capture.NewHandle(iface)
	if err != nil {
		return nil, err
	}
	sniffer := NewUDPSniffer(logger, handle, hops)
	writer := NewUDPWriter(logger, senders)
	if err := sniffer.StartCapturing(); err != nil {
		handle.Close()
		return nil, err
	}
	return &UDPStack{Sniffer: sniffer, Writer: writer}, nil
}
