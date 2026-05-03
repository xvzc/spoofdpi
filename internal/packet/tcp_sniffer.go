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

	nhopCache  cache.Cache[netutil.IPKey]
	defaultTTL uint8

	handle Handle
}

func NewTCPSniffer(
	logger zerolog.Logger,
	cache cache.Cache[netutil.IPKey],
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

// --- HopTracker Methods ---

func (ts *TCPSniffer) Cache() cache.Cache[netutil.IPKey] {
	return ts.nhopCache
}

// StartCapturing begins monitoring for SYN/ACK packets in a background goroutine.
func (ts *TCPSniffer) StartCapturing() {
	// Create a new packet source from the handle.
	packetSource := gopacket.NewPacketSource(ts.handle, ts.handle.LinkType())
	packets := packetSource.Packets()
	// _ = ht.handle.SetBPFRawInstructionFilter(generateSynAckFilter())
	_ = ts.handle.ClearBPF()
	_ = ts.handle.SetBPFRawInstructionFilter(generateSynAckFilter(ts.handle.LinkType()))

	// Start a dedicated goroutine to process incoming packets.
	go func() {
		// Create a base context for this goroutine.
		for packet := range packets {
			ts.processPacket(session.WithNewTraceID(context.Background()), packet)
		}
	}()
}

// RegisterUntracked registers new IP addresses for tracking.
// Addresses that are already being tracked are ignored.
func (ts *TCPSniffer) RegisterUntracked(addrs []net.IP) {
	for _, v := range addrs {
		ts.nhopCache.Store(
			netutil.NewIPKey(v),
			ts.defaultTTL,
			cache.Options().WithSkipExisting(true),
		)
	}
}

// GetOptimalTTL retrieves the estimated hop count for a given key from the cache.
// It returns the hop count and true if found, or 0 and false if not found.
func (ts *TCPSniffer) GetOptimalTTL(key netutil.IPKey) uint8 {
	hopCount := uint8(255)
	if oTTL, ok := ts.nhopCache.Fetch(key); ok {
		hopCount = oTTL.(uint8)
	}

	return max(hopCount, 2) - 1
}

// processPacket analyzes a single packet to find SYN/ACKs and store hop counts.
func (ts *TCPSniffer) processPacket(ctx context.Context, p gopacket.Packet) {
	logger := logging.WithLocalScope(ctx, ts.logger, "sniff")

	tcpLayer := p.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		// log.Trace().Msgf("no tcp: %s", p.String())
		return
	}

	tcp, _ := tcpLayer.(*layers.TCP)
	if !tcp.SYN || !tcp.ACK {
		// log.Trace().Msgf("invalid packet: %s", p.String())
		return
	}

	// Check for a TCP layer
	var srcIP []byte
	var ttlLeft uint8

	// Handle IPv4
	if ipLayer := p.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		// Skip packets from local/private IPs (outgoing packets)
		if isLocalIP(ip.SrcIP) {
			return
		}

		srcIP = ip.SrcIP
		ttlLeft = ip.TTL
	} else if ipLayer := p.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		// Handle IPv6
		ip, _ := ipLayer.(*layers.IPv6)
		srcIP = ip.SrcIP
		ttlLeft = ip.HopLimit
	} else {
		return // No IP layer found
	}

	// Create the cache key: ServerIP:ServerPort
	// (The source of the SYN/ACK is the server)
	key := netutil.NewIPKey(srcIP)
	// Calculate hop count from the TTL
	nhops := estimateHops(ttlLeft)

	stored, exists := ts.nhopCache.Fetch(key)

	if ts.nhopCache.Store(key, nhops, cache.Options().WithUpdateExistingOnly(true)) {
		if !exists || stored != nhops {
			logger.Trace().
				Str("from", key.String()).
				Uint8("nhops", nhops).
				Uint8("ttlLeft", ttlLeft).
				Msgf("ttl(tcp) update")
		}
	}
}

// GenerateSynAckFilter creates a BPF program for "ip and tcp and (tcp[13] & 18 == 18)".
// This captures only TCP SYN-ACK packets (IPv4).
// GenerateSynAckFilter creates a BPF program adapted to the LinkType.
// It supports Ethernet, Null (Loopback/VPN), and Raw IP link types.
func generateSynAckFilter(linkType layers.LinkType) []BPFInstruction {
	var baseOffset uint32

	// Determine the offset where the IP header begins
	switch linkType {
	case layers.LinkTypeEthernet:
		baseOffset = 14
	case layers.LinkTypeNull, layers.LinkTypeLoop: // BSD Loopback / macOS utun
		baseOffset = 4
	case layers.LinkTypeRaw: // Linux TUN
		baseOffset = 0
	default:
		// Fallback to Ethernet or handle error if necessary
		baseOffset = 14
	}

	instructions := []BPFInstruction{}

	// 1. Protocol Verification (IPv4)
	if linkType == layers.LinkTypeEthernet {
		// Check EtherType == IPv4 (0x0800) at offset 12
		instructions = append(
			instructions,
			BPFInstruction{Op: 0x28, Jt: 0, Jf: 0, K: 12}, // Ldh [12]
			BPFInstruction{
				Op: 0x15,
				Jt: 0,
				Jf: 8,
				K:  0x0800,
			}, // Jeq 0x800, True, False(Skip to End)
		)
	} else {
		// Check IP Version == 4 at the base offset
		// Load byte at baseOffset, mask 0xF0, check if 0x40
		instructions = append(
			instructions,
			// BPFInstruction{Op: 0x30, Jt: 0, Jf: 0, K: baseOffset}, // Ldb [baseOffset]
			BPFInstruction{Op: 0x54, Jt: 0, Jf: 0, K: 0xf0}, // And 0xf0
			BPFInstruction{
				Op: 0x15,
				Jt: 0,
				Jf: 8,
				K:  0x40,
			}, // Jeq 0x40, True, False(Skip to End)
		)
	}

	// 2. Check Protocol == TCP (6)
	// Protocol field is at IP header + 9 bytes
	instructions = append(instructions,
		BPFInstruction{Op: 0x30, Jt: 0, Jf: 0, K: baseOffset + 9}, // Ldb [baseOffset + 9]
		BPFInstruction{Op: 0x15, Jt: 0, Jf: 6, K: 6},              // Jeq 6, True, False
	)

	// 3. Check Fragmentation (Flags & Fragment Offset)
	// At IP header + 6 bytes
	instructions = append(
		instructions,
		BPFInstruction{Op: 0x28, Jt: 0, Jf: 0, K: baseOffset + 6}, // Ldh [baseOffset + 6]
		BPFInstruction{
			Op: 0x45,
			Jt: 4,
			Jf: 0,
			K:  0x1fff,
		}, // Jset 0x1fff, True(Skip), False
	)

	// 4. Find TCP Header Start
	// Load IP IHL from (baseOffset), multiply by 4 to get length, store in X
	instructions = append(instructions,
		BPFInstruction{Op: 0xb1, Jt: 0, Jf: 0, K: baseOffset}, // Ldxb 4*([baseOffset]&0xf)
	)

	// 5. Check TCP Flags (SYN+ACK)
	// We need to load: baseOffset + IP_Len(X) + TCP_Flags(13)
	// Instruction: Load [X + K] -> K = baseOffset + 13
	instructions = append(
		instructions,
		BPFInstruction{
			Op: 0x50,
			Jt: 0,
			Jf: 0,
			K:  baseOffset + 13,
		}, // Ldb [X + baseOffset + 13]
		BPFInstruction{Op: 0x54, Jt: 0, Jf: 0, K: 18}, // And 18 (SYN|ACK)
		BPFInstruction{Op: 0x15, Jt: 0, Jf: 1, K: 18}, // Jeq 18, True, False
	)

	// 6. Capture
	instructions = append(instructions,
		BPFInstruction{Op: 0x6, Jt: 0, Jf: 0, K: 0x00040000}, // Ret capture_len
		BPFInstruction{Op: 0x6, Jt: 0, Jf: 0, K: 0x00000000}, // Ret 0
	)

	return instructions
}
