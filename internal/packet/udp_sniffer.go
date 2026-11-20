package packet

import (
	"context"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/cache"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/logging"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/session"
)

var _ Sniffer = (*UDPSniffer)(nil)

type UDPSniffer struct {
	logger zerolog.Logger

	nhopCache  cache.Cache[netutil.IPKey, HopEntry]
	defaultTTL uint8

	handle Handle
}

func NewUDPSniffer(
	logger zerolog.Logger,
	handle Handle,
	cache cache.Cache[netutil.IPKey, HopEntry],
	cfg *config.RuntimeConfig,
) *UDPSniffer {
	return &UDPSniffer{
		logger:     logger,
		handle:     handle,
		nhopCache:  cache,
		defaultTTL: uint8(cfg.Conn.DefaultFakeTTL),
	}
}

// StartCapturing begins monitoring for UDP packets in a background goroutine.
func (us *UDPSniffer) StartCapturing() {
	_ = us.handle.ClearBPF()
	_ = us.handle.SetBPFRawInstructionFilter(generateUdpFilter(us.handle.LinkType()))

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
			HopEntry{Hops: us.defaultTTL, Learned: false},
			cache.Options().WithSkipExisting(true),
		)
	}
}

// GetOptimalTTL retrieves the estimated hop count for a given key from the cache.
func (us *UDPSniffer) GetOptimalTTL(key netutil.IPKey) uint8 {
	hopCount := uint8(255)
	if e, ok := us.nhopCache.Get(key); ok {
		hopCount = e.Hops
	}

	return max(hopCount, 2) - 1
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

	udpLayer := p.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}

	var srcIP, dstIP net.IP
	var ttlLeft uint8

	if ipLayer := p.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		srcIP = ip.SrcIP
		dstIP = ip.DstIP
		ttlLeft = ip.TTL
	} else if ipLayer := p.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv6)
		srcIP = ip.SrcIP
		dstIP = ip.DstIP
		ttlLeft = ip.HopLimit
	} else {
		return
	}

	// A packet from an address to itself is not a reply from a server;
	// learning from it would record a bogus hop count.
	if srcIP.Equal(dstIP) {
		return
	}

	key := netutil.NewIPKey(srcIP)
	nhops := estimateHops(ttlLeft)

	prev, exists := us.nhopCache.Get(key)
	if !exists {
		return
	}

	us.nhopCache.Set(key, HopEntry{Hops: nhops, Learned: true}, nil)
	if nhops != prev.Hops {
		logger.Trace().
			Str("from", key.String()).
			Uint8("nhops", nhops).
			Uint8("ttlLeft", ttlLeft).
			Msgf("ttl(udp) update")
	}
}

// generateUdpFilter creates a BPF program for "ip and udp".
// It supports Ethernet, Null (Loopback/VPN), and Raw IP link types.
func generateUdpFilter(linkType layers.LinkType) []BPFInstruction {
	var baseOffset uint32

	switch linkType {
	case layers.LinkTypeEthernet:
		baseOffset = 14
	case layers.LinkTypeNull, layers.LinkTypeLoop:
		baseOffset = 4
	case layers.LinkTypeRaw:
		baseOffset = 0
	default:
		baseOffset = 14
	}

	instructions := []BPFInstruction{}

	// 1. Protocol Verification (IPv4)
	if linkType == layers.LinkTypeEthernet {
		instructions = append(
			instructions,
			BPFInstruction{Op: 0x28, Jt: 0, Jf: 0, K: 12},
			BPFInstruction{Op: 0x15, Jt: 0, Jf: 3, K: 0x0800},
		)
	} else {
		instructions = append(
			instructions,
			BPFInstruction{Op: 0x30, Jt: 0, Jf: 0, K: baseOffset},
			BPFInstruction{Op: 0x54, Jt: 0, Jf: 0, K: 0xf0},
			BPFInstruction{Op: 0x15, Jt: 0, Jf: 3, K: 0x40},
		)
	}

	// 2. Check Protocol == UDP (17)
	instructions = append(instructions,
		BPFInstruction{Op: 0x30, Jt: 0, Jf: 0, K: baseOffset + 9},
		BPFInstruction{Op: 0x15, Jt: 0, Jf: 1, K: 17},
	)

	// 3. Capture
	instructions = append(instructions,
		BPFInstruction{Op: 0x6, Jt: 0, Jf: 0, K: 0x00040000},
		BPFInstruction{Op: 0x6, Jt: 0, Jf: 0, K: 0x00000000},
	)

	return instructions
}
