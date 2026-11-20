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

var _ Sniffer = (*TCPSniffer)(nil)

type TCPSniffer struct {
	logger zerolog.Logger

	nhopCache cache.Cache[netutil.IPKey, HopEntry]
	hops      HopPolicy
	seqs      *SeqTracker

	handle Handle
}

func NewTCPSniffer(
	logger zerolog.Logger,
	handle Handle,
	cache cache.Cache[netutil.IPKey, HopEntry],
	seqs *SeqTracker,
	cfg *config.RuntimeConfig,
) *TCPSniffer {
	return &TCPSniffer{
		logger:    logger,
		handle:    handle,
		nhopCache: cache,
		hops:      NewHopPolicy(cfg.Conn),
		seqs:      seqs,
	}
}

// StartCapturing begins monitoring for SYN/ACK packets in a background goroutine.
func (ts *TCPSniffer) StartCapturing() {
	_ = ts.handle.ClearBPF()
	_ = ts.handle.SetBPFRawInstructionFilter(generateSynAckFilter(ts.handle.LinkType()))

	packetSource := gopacket.NewPacketSource(ts.handle, ts.handle.LinkType())
	packets := packetSource.Packets()

	go func() {
		for packet := range packets {
			ts.processPacket(session.WithNewTraceID(context.Background()), packet)
		}
	}()
}

// Register registers new IP addresses for hop-count learning.
// Addresses that are already being tracked are ignored.
func (ts *TCPSniffer) Register(addrs []net.IP) {
	for _, v := range addrs {
		ts.nhopCache.Set(
			netutil.NewIPKey(v),
			HopEntry{Hops: ts.hops.Default, Learned: false},
			cache.Options().WithSkipExisting(true),
		)
	}
}

// GetOptimalTTL retrieves the estimated hop count for a given key from the cache.
func (ts *TCPSniffer) GetOptimalTTL(key netutil.IPKey) uint8 {
	e, ok := ts.nhopCache.Get(key)
	return ts.hops.TTL(e, ok)
}

// LearnedHops returns the hop count for key and whether it was learned
// from a captured packet.
func (ts *TCPSniffer) LearnedHops(key netutil.IPKey) (uint8, bool) {
	e, ok := ts.nhopCache.Get(key)
	if !ok || !e.Learned {
		return 0, false
	}
	return e.Hops, true
}

// processPacket analyzes a single packet to find SYN/ACKs and store hop
// counts and the connection's sequence numbers.
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

	prev, exists := ts.nhopCache.Get(key)
	if !exists {
		return
	}

	ts.nhopCache.Set(key, HopEntry{Hops: nhops, Learned: true}, nil)

	// The SYN/ACK's Ack is the client's next sequence number, and the
	// client acknowledges the server's SYN with Seq+1.
	if ts.seqs != nil {
		ts.seqs.Put(
			netutil.NewNATKey(dstIP, int(tcp.DstPort), srcIP, int(tcp.SrcPort)),
			SeqAck{Seq: tcp.Ack, Ack: tcp.Seq + 1},
		)
	}
	if nhops != prev.Hops {
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
		// Load EtherType (2 bytes at offset 12), then check for IPv4 (0x0800).
		// On mismatch, jump 8 forward to the reject instruction.
		instructions = append(
			instructions,
			BPFInstruction{Op: 0x28, Jt: 0, Jf: 0, K: 12},
			BPFInstruction{Op: 0x15, Jt: 0, Jf: 8, K: 0x0800},
		)
	} else {
		// For Null/Loop/Raw link types the packet starts with a 4-byte family
		// field (Null/Loop) or directly with the IP header (Raw), so there is
		// no EtherType to check.  Instead, load the first byte of the IP
		// header (version | IHL), mask the upper nibble with 0xf0, and verify
		// it equals 0x40 (IP version 4).  The load must come first; without
		// it the accumulator is 0 and the check always fails, silently
		// dropping every packet on these link types.
		// This section emits 3 instructions (vs 2 for Ethernet), so the false
		// jump offset is 7, not 8.
		instructions = append(
			instructions,
			BPFInstruction{Op: 0x30, Jt: 0, Jf: 0, K: baseOffset}, // ldb [baseOffset]
			BPFInstruction{Op: 0x54, Jt: 0, Jf: 0, K: 0xf0},       // and #0xf0
			BPFInstruction{Op: 0x15, Jt: 0, Jf: 7, K: 0x40},       // jeq #0x40
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
