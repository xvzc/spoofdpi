package capture

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// SynAck is a captured TCP SYN/ACK.
type SynAck struct {
	Src, Dst         net.IP
	SrcPort, DstPort uint16
	Seq, Ack         uint32
	// TTLLeft is the IPv4 TTL or IPv6 hop limit the packet arrived with,
	// and Hops the hop count estimated from it (see EstimateHops).
	TTLLeft, Hops uint8
}

// ParseSynAck returns the SYN/ACK carried by p. ok is false if p is not an
// IPv4 or IPv6 TCP packet with both SYN and ACK set, or if it is sent from
// an address to itself: such a packet is not a reply from a server, and
// learning from it would record a bogus hop count.
func ParseSynAck(p gopacket.Packet) (sa SynAck, ok bool) {
	tcpLayer := p.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return SynAck{}, false
	}

	tcp, _ := tcpLayer.(*layers.TCP)
	if !tcp.SYN || !tcp.ACK {
		return SynAck{}, false
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
		return SynAck{}, false
	}

	if srcIP.Equal(dstIP) {
		return SynAck{}, false
	}

	return SynAck{
		Src:     srcIP,
		Dst:     dstIP,
		SrcPort: uint16(tcp.SrcPort),
		DstPort: uint16(tcp.DstPort),
		Seq:     tcp.Seq,
		Ack:     tcp.Ack,
		TTLLeft: ttlLeft,
		Hops:    EstimateHops(ttlLeft),
	}, true
}

// EstimateHops estimates the number of hops based on TTL, assuming the
// sender started from the nearest common initial TTL (64, 128 or 255).
// This logic is based on the hop counting mechanism from GoodbyeDPI.
// It returns 0 when the TTL is unchanged, i.e. the sender is on the local
// link.
func EstimateHops(ttlLeft uint8) uint8 {
	// Unrecognizable initial TTL
	estimatedInitialHops := uint8(255)
	switch {
	case ttlLeft <= 64:
		estimatedInitialHops = 64
	case ttlLeft <= 128:
		estimatedInitialHops = 128
	default:
		estimatedInitialHops = 255
	}

	return estimatedInitialHops - ttlLeft
}

// SynAckFilter returns a BPF program that accepts IPv4 TCP SYN/ACKs on the
// given link type. It supports Ethernet, Null/Loop (loopback and VPN), Raw
// IP, and PPP, and returns ErrUnsupportedLinkType for any other.
func SynAckFilter(linkType layers.LinkType) ([]BPFInstruction, error) {
	return buildForLink(linkType, synAckProgram)
}

// synAckProgram is the SYN/ACK filter for the frames of layout l.
func synAckProgram(l linkLayout) []BPFInstruction {
	baseOffset := l.base

	// 1. Protocol Verification (IPv4). The false jump lands on the reject
	// instruction, 9 forward.
	instructions := l.ipv4Check(9)

	// 2. Check Protocol == TCP (6)
	instructions = append(instructions,
		BPFInstruction{Op: 0x30, Jt: 0, Jf: 0, K: baseOffset + 9},
		BPFInstruction{Op: 0x15, Jt: 0, Jf: 7, K: 6},
	)

	// 3. Check Fragmentation
	instructions = append(
		instructions,
		BPFInstruction{Op: 0x28, Jt: 0, Jf: 0, K: baseOffset + 6},
		BPFInstruction{Op: 0x45, Jt: 5, Jf: 0, K: 0x1fff},
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
