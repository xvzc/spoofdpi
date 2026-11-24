package packet

import (
	"context"
	"errors"
	"net"

	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog"
)

var _ Writer = (*UDPWriter)(nil)

type UDPWriter struct {
	logger zerolog.Logger

	senders Senders
}

func NewUDPWriter(logger zerolog.Logger, senders Senders) *UDPWriter {
	return &UDPWriter{
		logger:  logger,
		senders: senders,
	}
}

// --- Injector Methods ---

// WriteCraftedPacket crafts a UDP datagram from a payload and sends it
// with TTL ttl through the sender of dst's family.
func (uw *UDPWriter) WriteCraftedPacket(
	ctx context.Context,
	src net.Addr,
	dst net.Addr,
	ttl uint8,
	payload []byte,
) (int, error) {
	srcUDP, ok := src.(*net.UDPAddr)
	if !ok {
		return 0, errors.New("src is not *net.UDPAddr")
	}

	dstUDP, ok := dst.(*net.UDPAddr)
	if !ok {
		return 0, errors.New("dst is not *net.UDPAddr")
	}

	udpLayer := &layers.UDP{
		SrcPort: layers.UDPPort(srcUDP.Port),
		DstPort: layers.UDPPort(dstUDP.Port),
	}
	err := uw.senders.send(
		srcUDP.IP,
		dstUDP.IP,
		ttl,
		layers.IPProtocolUDP,
		udpLayer,
		payload,
	)
	if err != nil {
		return 0, err
	}

	return len(payload), nil
}
