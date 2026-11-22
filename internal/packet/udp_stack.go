package packet

import (
	"net"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/capture"
)

// UDPStack is what fake UDP packets are sent with: a sniffer that learns
// hop counts, and a writer that injects crafted packets, sharing one
// capture handle.
type UDPStack struct {
	Sniffer *UDPSniffer
	Writer  *UDPWriter
}

// OpenUDPStack opens one capture handle on iface, shared by a sniffer that
// records hop counts in hops and a writer that injects packets to
// gatewayMAC, and starts the sniffer. It fails, closing the handle, if the
// sniffer cannot start. The handle stays open for the life of the process:
// the sniffer reads it until then.
func OpenUDPStack(
	logger zerolog.Logger,
	iface *net.Interface,
	gatewayMAC net.HardwareAddr,
	hops *HopStore,
) (*UDPStack, error) {
	handle, err := capture.NewHandle(iface)
	if err != nil {
		return nil, err
	}
	sniffer := NewUDPSniffer(logger, handle, hops)
	writer := NewUDPWriter(logger, handle, iface, gatewayMAC)
	if err := sniffer.StartCapturing(); err != nil {
		handle.Close()
		return nil, err
	}
	return &UDPStack{Sniffer: sniffer, Writer: writer}, nil
}
