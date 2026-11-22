package packet

import (
	"context"
	"net"

	"github.com/google/gopacket"
	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/cache"
	"github.com/xvzc/spoofdpi/internal/capture"
	"github.com/xvzc/spoofdpi/internal/logging"
	"github.com/xvzc/spoofdpi/internal/netutil"
)

var _ Sniffer = (*UDPSniffer)(nil)

type UDPSniffer struct {
	logger zerolog.Logger

	nhopCache cache.Cache[netutil.IPKey, HopEntry]

	handle capture.Handle
}

func NewUDPSniffer(
	logger zerolog.Logger,
	handle capture.Handle,
	cache cache.Cache[netutil.IPKey, HopEntry],
) *UDPSniffer {
	return &UDPSniffer{
		logger:    logger,
		handle:    handle,
		nhopCache: cache,
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

// Register registers new IP addresses for hop-count learning.
// Addresses that are already being tracked are ignored.
func (us *UDPSniffer) Register(addrs []net.IP) {
	for _, v := range addrs {
		us.nhopCache.Set(
			netutil.NewIPKey(v),
			HopEntry{},
			cache.Options().WithSkipExisting(true),
		)
	}
}

// Hops returns the hop-count cache entry of key, and whether key is cached.
func (us *UDPSniffer) Hops(key netutil.IPKey) (HopEntry, bool) {
	return us.nhopCache.Get(key)
}

// processPacket analyzes a single packet to store hop counts.
func (us *UDPSniffer) processPacket(ctx context.Context, p gopacket.Packet) {
	logger := logging.WithLocalScope(ctx, us.logger, "sniff")

	u, ok := capture.ParseUDP(p)
	if !ok {
		return
	}

	key := netutil.NewIPKey(u.Src)
	nhops := u.Hops

	// prev only feeds the trace log below. The update-only Set decides
	// whether key is registered, so a key evicted after this Get is not
	// re-inserted.
	prev, _ := us.nhopCache.Get(key)
	if !us.nhopCache.Set(
		key,
		HopEntry{Hops: nhops, Learned: true},
		cache.Options().WithUpdateExistingOnly(true),
	) {
		return
	}
	if !prev.Learned || nhops != prev.Hops {
		logger.Trace().
			Str("from", key.String()).
			Uint8("nhops", nhops).
			Uint8("ttlLeft", u.TTLLeft).
			Msgf("ttl(udp) update")
	}
}
