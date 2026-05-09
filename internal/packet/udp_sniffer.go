package packet

import (
	"context"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/cache"
	"github.com/xvzc/spoofdpi/internal/logging"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/session"
)

var _ Sniffer = (*UDPSniffer)(nil)

type UDPSniffer struct {
	logger zerolog.Logger

	nhopCache  cache.Cache[netutil.IPKey, uint8]
	defaultTTL uint8

	handle Handle
}

func NewUDPSniffer(
	logger zerolog.Logger,
	cache cache.Cache[netutil.IPKey, uint8],
	handle Handle,
	defaultTTL uint8,
) *UDPSniffer {
	return &UDPSniffer{
		logger:     logger,
		nhopCache:  cache,
		handle:     handle,
		defaultTTL: defaultTTL,
	}
}

func (us *UDPSniffer) Cache() cache.Cache[netutil.IPKey, uint8] {
	return us.nhopCache
}

// StartCapturing begins monitoring for UDP packets in a background goroutine.
func (us *UDPSniffer) StartCapturing() {
	packetSource := gopacket.NewPacketSource(us.handle, us.handle.LinkType())
	packets := packetSource.Packets()

	_ = us.handle.ClearBPF()
	_ = us.handle.SetBPFRawInstructionFilter(generateUdpFilter(us.handle.LinkType()))

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
			us.defaultTTL,
			cache.Options().WithSkipExisting(true),
		)
	}
}

// GetOptimalTTL retrieves the estimated hop count for a given key from the cache.
func (us *UDPSniffer) GetOptimalTTL(key netutil.IPKey) uint8 {
	hopCount := uint8(255)
	if oTTL, ok := us.nhopCache.Get(key); ok {
		hopCount = oTTL
	}

	return max(hopCount, 2) - 1
}

// processPacket analyzes a single packet to store hop counts.
func (us *UDPSniffer) processPacket(ctx context.Context, p gopacket.Packet) {
	logger := logging.WithLocalScope(ctx, us.logger, "sniff")

	udpLayer := p.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}

	var srcIP []byte
	var ttlLeft uint8

	if ipLayer := p.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)

		if isLocalIP(ip.SrcIP) {
			return
		}
		if !isLocalIP(ip.DstIP) {
			return
		}

		srcIP = ip.SrcIP
		ttlLeft = ip.TTL
	} else if ipLayer := p.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv6)
		srcIP = ip.SrcIP
		ttlLeft = ip.HopLimit
	} else {
		return
	}

	key := netutil.NewIPKey(srcIP)
	nhops := estimateHops(ttlLeft)

	_, exists := us.nhopCache.Get(key)
	if !exists {
		return
	}

	if us.nhopCache.Set(key, nhops, nil) {
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
