package capture

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/xvzc/spoofdpi/internal/netutil"
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

// SynAckFilter returns a BPF program that accepts the TCP SYN/ACKs of the
// address families in fams on the given link type. Over IPv6, it accepts
// SYN/ACKs right after the IPv6 header and, without checking what follows,
// packets whose first next header is a hop-by-hop (0), routing (43), or
// destination options (60) header, which ParseSynAck sorts out. It rejects
// fragments (44) and every other next header, such as AH (51) or ESP (50).
// It supports Ethernet, Null/Loop (loopback and VPN), Raw IP, and PPP,
// and returns ErrUnsupportedLinkType for any other, and ErrNoFamily for an
// empty fams.
func SynAckFilter(
	linkType layers.LinkType,
	fams netutil.FamilySet,
) ([]BPFInstruction, error) {
	build, err := familyProgram(fams, synAckIPv4Program, synAckIPv6Program)
	if err != nil {
		return nil, err
	}
	return buildForLink(linkType, build)
}

// synAckIPv4Program is the IPv4 SYN/ACK filter for the frames of layout l.
// A frame that is not IPv4 goes to the instruction after the program when
// nextBranch is set.
func synAckIPv4Program(l linkLayout, nextBranch bool) []BPFInstruction {
	baseOffset := l.base

	// 1. Protocol Verification (IPv4). The false jump lands on the reject
	// instruction, 9 forward, or on the next branch past it.
	rejectJf := uint8(9)
	if nextBranch {
		rejectJf++
	}
	instructions := l.ipv4Check(rejectJf)

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

// synAckIPv6Program is the IPv6 SYN/ACK filter for the frames of layout l.
func synAckIPv6Program(l linkLayout) []BPFInstruction {
	base := l.base

	// The false jump lands on the reject instruction, 9 forward.
	instructions := l.ipv6Check(9)
	return append(
		instructions,
		BPFInstruction{Op: 0x30, K: base + 6},            // ldb [next header]
		BPFInstruction{Op: 0x15, Jt: 3, K: 6},            // jeq #TCP -> flags
		BPFInstruction{Op: 0x15, Jt: 5, K: ipv6HopByHop}, // jeq #0 -> accept
		BPFInstruction{Op: 0x15, Jt: 4, K: ipv6Routing},  // jeq #43 -> accept
		// jeq #60 -> accept, else reject
		BPFInstruction{Op: 0x15, Jt: 3, Jf: 4, K: ipv6DestOptions},
		BPFInstruction{Op: 0x30, K: base + ipv6HeaderLen + 13}, // ldb [TCP flags]
		BPFInstruction{Op: 0x54, K: 0x12},                      // and #SYN|ACK
		BPFInstruction{Op: 0x15, Jf: 1, K: 0x12},               // jeq #SYN|ACK
		BPFInstruction{Op: 0x6, K: 0x00040000},                 // accept
		BPFInstruction{Op: 0x6, K: 0},                          // reject
	)
}
