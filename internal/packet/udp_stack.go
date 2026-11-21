package packet

import (
	"net"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/cache"
	"github.com/xvzc/spoofdpi/internal/capture"
	"github.com/xvzc/spoofdpi/internal/netutil"
)

// UDPStack is what fake UDP packets are sent with: a sniffer that learns
// hop counts, and a writer that injects crafted packets, sharing one
// capture handle.
type UDPStack struct {
	Sniffer *UDPSniffer
	Writer  *UDPWriter
}

// OpenUDPStack opens one capture handle on iface, shared by a sniffer that
// records hop counts in hopCache and a writer that injects packets to
// gatewayMAC, and starts the sniffer. The handle stays open for the life of
// the process: the sniffer reads it until then.
func OpenUDPStack(
	logger zerolog.Logger,
	iface *net.Interface,
	gatewayMAC net.HardwareAddr,
	hopCache cache.Cache[netutil.IPKey, HopEntry],
) (*UDPStack, error) {
	handle, err := capture.NewHandle(iface)
	if err != nil {
		return nil, err
	}
	sniffer := NewUDPSniffer(logger, handle, hopCache)
	writer := NewUDPWriter(logger, handle, iface, gatewayMAC)
	sniffer.StartCapturing()
	return &UDPStack{Sniffer: sniffer, Writer: writer}, nil
}
