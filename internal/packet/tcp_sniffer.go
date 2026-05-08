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

var _ Sniffer = (*TCPSniffer)(nil)

type TCPSniffer struct {
	logger zerolog.Logger

	nhopCache  cache.Cache[netutil.IPKey, uint8]
	defaultTTL uint8

	handle Handle
}

func NewTCPSniffer(
	logger zerolog.Logger,
	cache cache.Cache[netutil.IPKey, uint8],
	handle Handle,
	defaultTTL uint8,
) *TCPSniffer {
	return &TCPSniffer{
		logger:     logger,
		nhopCache:  cache,
		handle:     handle,
		defaultTTL: defaultTTL,
	}
}

func (ts *TCPSniffer) Cache() cache.Cache[netutil.IPKey, uint8] {
	return ts.nhopCache
}

// StartCapturing begins monitoring for SYN/ACK packets in a background goroutine.
func (ts *TCPSniffer) StartCapturing() {
	packetSource := gopacket.NewPacketSource(ts.handle, ts.handle.LinkType())
	packets := packetSource.Packets()
	_ = ts.handle.ClearBPF()
	_ = ts.handle.SetBPFRawInstructionFilter(generateSynAckFilter(ts.handle.LinkType()))

	go func() {
		for packet := range packets {
			ts.processPacket(session.WithNewTraceID(context.Background()), packet)
		}
	}()
}

// Track registers new IP addresses for hop-count learning.
// Addresses that are already being tracked are ignored.
func (ts *TCPSniffer) Track(addrs []net.IP) {
	for _, v := range addrs {
		ts.nhopCache.Set(
			netutil.NewIPKey(v),
			ts.defaultTTL,
			cache.Options().WithSkipExisting(true),
		)
	}
}

// GetOptimalTTL retrieves the estimated hop count for a given key from the cache.
func (ts *TCPSniffer) GetOptimalTTL(key netutil.IPKey) uint8 {
	hopCount := uint8(255)
	if oTTL, ok := ts.nhopCache.Get(key); ok {
		hopCount = oTTL
	}

	return max(hopCount, 2) - 1
}

// processPacket analyzes a single packet to find SYN/ACKs and store hop counts.
func (ts *TCPSniffer) processPacket(ctx context.Context, p gopacket.Packet) {
	logger := logging.WithLocalScope(ctx, ts.logger, "sniff")

	tcpLayer := p.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}

	tcp, _ := tcpLayer.(*layers.TCP)
	if !tcp.SYN || !tcp.ACK {
		return
	}

	var srcIP []byte
	var ttlLeft uint8

	if ipLayer := p.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		if isLocalIP(ip.SrcIP) {
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

	_, exists := ts.nhopCache.Get(key)
	if !exists {
		return
	}

	if ts.nhopCache.Set(key, nhops, nil) {
		logger.Trace().
			Str("from", key.String()).
			Uint8("nhops", nhops).
			Uint8("ttlLeft", ttlLeft).
			Msgf("ttl(tcp) update")
	}
}

// generateSynAckFilter creates a BPF program adapted to the LinkType.
// It supports Ethernet, Null (Loopback/VPN), and Raw IP link types.
func generateSynAckFilter(linkType layers.LinkType) []BPFInstruction {
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
			BPFInstruction{Op: 0x15, Jt: 0, Jf: 8, K: 0x0800},
		)
	} else {
		instructions = append(
			instructions,
			BPFInstruction{Op: 0x54, Jt: 0, Jf: 0, K: 0xf0},
			BPFInstruction{Op: 0x15, Jt: 0, Jf: 8, K: 0x40},
		)
	}

	// 2. Check Protocol == TCP (6)
	instructions = append(instructions,
		BPFInstruction{Op: 0x30, Jt: 0, Jf: 0, K: baseOffset + 9},
		BPFInstruction{Op: 0x15, Jt: 0, Jf: 6, K: 6},
	)

	// 3. Check Fragmentation
	instructions = append(
		instructions,
		BPFInstruction{Op: 0x28, Jt: 0, Jf: 0, K: baseOffset + 6},
		BPFInstruction{Op: 0x45, Jt: 4, Jf: 0, K: 0x1fff},
	)

	// 4. Find TCP Header Start
	instructions = append(instructions,
		BPFInstruction{Op: 0xb1, Jt: 0, Jf: 0, K: baseOffset},
	)

	// 5. Check TCP Flags (SYN+ACK)
	instructions = append(
		instructions,
		BPFInstruction{Op: 0x50, Jt: 0, Jf: 0, K: baseOffset + 13},
		BPFInstruction{Op: 0x54, Jt: 0, Jf: 0, K: 18},
		BPFInstruction{Op: 0x15, Jt: 0, Jf: 1, K: 18},
	)

	// 6. Capture
	instructions = append(instructions,
		BPFInstruction{Op: 0x6, Jt: 0, Jf: 0, K: 0x00040000},
		BPFInstruction{Op: 0x6, Jt: 0, Jf: 0, K: 0x00000000},
	)

	return instructions
}
