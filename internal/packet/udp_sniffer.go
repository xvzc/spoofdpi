package packet

import (
	"context"

	"github.com/google/gopacket"
	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/capture"
	"github.com/xvzc/spoofdpi/internal/logging"
	"github.com/xvzc/spoofdpi/internal/netutil"
)

var _ Sniffer = (*UDPSniffer)(nil)

type UDPSniffer struct {
	logger zerolog.Logger

	hops *HopStore

	handle capture.Handle
}

func NewUDPSniffer(
	logger zerolog.Logger,
	handle capture.Handle,
	hops *HopStore,
) *UDPSniffer {
	return &UDPSniffer{
		logger: logger,
		handle: handle,
		hops:   hops,
	}
}

// StartCapturing begins monitoring for UDP packets in a background goroutine.
func (us *UDPSniffer) StartCapturing() {
	_ = us.handle.ClearBPF()
	_ = us.handle.SetBPFRawInstructionFilter(capture.UDPFilter(us.handle.LinkType()))

	packetSource := gopacket.NewPacketSource(us.handle, us.handle.LinkType())
	packets := packetSource.Packets()

	go func() {
		for packet := range packets {
			us.processPacket(
				logging.ContextWithTraceID(context.Background(), logging.NewTraceID()),
				packet,
			)
		}
	}()
}

// processPacket analyzes a single packet to store hop counts.
func (us *UDPSniffer) processPacket(ctx context.Context, p gopacket.Packet) {
	logger := logging.WithLocalScope(ctx, us.logger, "sniff")

	u, ok := capture.ParseUDP(p)
	if !ok {
		return
	}

	nhops := u.Hops

	prev, registered := us.hops.Learn(ProtoUDP, u.Src, nhops)
	if !registered {
		return
	}
	if !prev.Learned || nhops != prev.Hops {
		logger.Trace().
			Str("from", netutil.NewIPKey(u.Src).String()).
			Uint8("nhops", nhops).
			Uint8("ttlLeft", u.TTLLeft).
			Msgf("ttl(udp) update")
	}
}
