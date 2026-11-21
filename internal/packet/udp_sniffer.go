package packet

import (
	"context"
	"net"

	"github.com/google/gopacket"
	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/cache"
	"github.com/xvzc/spoofdpi/internal/capture"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/logging"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/session"
)

var _ Sniffer = (*UDPSniffer)(nil)

type UDPSniffer struct {
	logger zerolog.Logger

	nhopCache cache.Cache[netutil.IPKey, HopEntry]
	hops      HopPolicy

	handle capture.Handle
}

func NewUDPSniffer(
	logger zerolog.Logger,
	handle capture.Handle,
	cache cache.Cache[netutil.IPKey, HopEntry],
	cfg *config.RuntimeConfig,
) *UDPSniffer {
	return &UDPSniffer{
		logger:    logger,
		handle:    handle,
		nhopCache: cache,
		hops:      NewHopPolicy(cfg.Conn),
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
			us.processPacket(session.WithNewTraceID(context.Background()), packet)
		}
	}()
}

// Register registers new IP addresses for hop-count learning.
// Addresses that are already being tracked are ignored.
func (us *UDPSniffer) Register(addrs []net.IP) {
	for _, v := range addrs {
		us.nhopCache.Set(
			netutil.NewIPKey(v),
			HopEntry{Hops: us.hops.Default, Learned: false},
			cache.Options().WithSkipExisting(true),
		)
	}
}

// GetOptimalTTL retrieves the estimated hop count for a given key from the cache.
func (us *UDPSniffer) GetOptimalTTL(key netutil.IPKey) uint8 {
	e, ok := us.nhopCache.Get(key)
	return us.hops.TTL(e, ok)
}

// LearnedHops returns the hop count for key and whether it was learned
// from a captured packet.
func (us *UDPSniffer) LearnedHops(key netutil.IPKey) (uint8, bool) {
	e, ok := us.nhopCache.Get(key)
	if !ok || !e.Learned {
		return 0, false
	}
	return e.Hops, true
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

	prev, exists := us.nhopCache.Get(key)
	if !exists {
		return
	}

	us.nhopCache.Set(key, HopEntry{Hops: nhops, Learned: true}, nil)
	if nhops != prev.Hops {
		logger.Trace().
			Str("from", key.String()).
			Uint8("nhops", nhops).
			Uint8("ttlLeft", u.TTLLeft).
			Msgf("ttl(udp) update")
	}
}
