package packet

import (
	"context"
	"fmt"

	"github.com/google/gopacket"
	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/capture"
	"github.com/xvzc/spoofdpi/internal/logging"
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

// StartCapturing begins monitoring for UDP packets in a background
// goroutine. It returns an error if the UDP filter cannot be built, in
// which case it wraps capture.ErrUnsupportedLinkType for a link type the
// filter does not support, or installed.
func (us *UDPSniffer) StartCapturing() error {
	// Detaching fails on a Linux socket that has no filter yet (ENOENT),
	// and attaching a filter replaces any previous one, so a failed clear
	// is harmless.
	_ = us.handle.ClearBPF()
	filter, err := capture.UDPFilter(us.handle.LinkType())
	if err != nil {
		return fmt.Errorf("build UDP capture filter: %w", err)
	}
	if err := us.handle.SetBPFRawInstructionFilter(filter); err != nil {
		return fmt.Errorf("set UDP capture filter: %w", err)
	}

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

	return nil
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
			Str("src", joinAddrPort(u.Src, u.SrcPort)).
			Str("dst", joinAddrPort(u.Dst, u.DstPort)).
			Uint8("nhops", nhops).
			Uint8("ttlLeft", u.TTLLeft).
			Msgf("ttl(udp) update")
	}
}
