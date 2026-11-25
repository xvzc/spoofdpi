package packet

import (
	"context"
	"fmt"

	"github.com/google/gopacket"
	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/logging"
	"github.com/xvzc/spoofdpi/internal/packetio/capture"
)

var _ Sniffer = (*UDPSniffer)(nil)

type UDPSniffer struct {
	logger zerolog.Logger
	// runID is the trace ID of the logs of the capture goroutine.
	runID string

	hops *HopStore

	handle capture.Handle
}

func NewUDPSniffer(
	runID string,
	logger zerolog.Logger,
	handle capture.Handle,
	hops *HopStore,
) *UDPSniffer {
	return &UDPSniffer{
		runID:  runID,
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

	// Every captured packet logs under the run's trace ID: a packet belongs
	// to no connection of its own.
	ctx := logging.ContextWithTraceID(context.Background(), us.runID)
	go func() {
		for packet := range packets {
			us.processPacket(ctx, packet)
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
