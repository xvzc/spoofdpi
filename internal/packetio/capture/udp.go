package capture

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/xvzc/spoofdpi/internal/netutil"
)

// UDPPacket is a captured UDP packet.
type UDPPacket struct {
	Src, Dst         net.IP
	SrcPort, DstPort uint16
	// TTLLeft is the IPv4 TTL or IPv6 hop limit the packet arrived with,
	// and Hops the hop count estimated from it (see EstimateHops).
	TTLLeft, Hops uint8
}

// ParseUDP returns the UDP packet carried by p. ok is false if p is not an
// IPv4 or IPv6 UDP packet, or if it is sent from an address to itself:
// such a packet is not a reply from a server, and learning from it would
// record a bogus hop count.
func ParseUDP(p gopacket.Packet) (u UDPPacket, ok bool) {
	udpLayer := p.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return UDPPacket{}, false
	}
	udp, _ := udpLayer.(*layers.UDP)

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
		return UDPPacket{}, false
	}

	if srcIP.Equal(dstIP) {
		return UDPPacket{}, false
	}

	return UDPPacket{
		Src:     srcIP,
		Dst:     dstIP,
		SrcPort: uint16(udp.SrcPort),
		DstPort: uint16(udp.DstPort),
		TTLLeft: ttlLeft,
		Hops:    EstimateHops(ttlLeft),
	}, true
}

// UDPFilter returns a BPF program that accepts the UDP packets of the
// address families in fams on the given link type: "ip and udp" for IPv4.
// Over IPv6, it accepts UDP right after the IPv6 header, and, like the
// IPv4 branch, which does not look at the fragment offset, any fragment
// (44) whose fragment header carries UDP, first or not. It also accepts,
// without checking what follows, packets whose first next header is a
// hop-by-hop (0), routing (43), or destination options (60) header, and
// rejects every other next header, such as AH (51) or ESP (50). ParseUDP
// drops fragments and packets that do not carry UDP. It supports Ethernet, Null/Loop (loopback and VPN), Raw IP, and PPP,
// and returns ErrUnsupportedLinkType for any other, and ErrNoFamily for an
// empty fams.
func UDPFilter(
	linkType layers.LinkType,
	fams netutil.FamilySet,
) ([]BPFInstruction, error) {
	build, err := familyProgram(fams, udpIPv4Program, udpIPv6Program)
	if err != nil {
		return nil, err
	}
	return buildForLink(linkType, build)
}

// udpIPv4Program is the IPv4 UDP filter for the frames of layout l. A
// frame that is not IPv4 goes to the instruction after the program when
// nextBranch is set.
func udpIPv4Program(l linkLayout, nextBranch bool) []BPFInstruction {
	baseOffset := l.base

	// 1. Protocol Verification (IPv4). The false jump lands on the reject
	// instruction, 3 forward, or on the next branch past it.
	rejectJf := uint8(3)
	if nextBranch {
		rejectJf++
	}
	instructions := l.ipv4Check(rejectJf)

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

// udpIPv6Program is the IPv6 UDP filter for the frames of layout l.
func udpIPv6Program(l linkLayout) []BPFInstruction {
	base := l.base

	// The false jump lands on the reject instruction, 9 forward.
	instructions := l.ipv6Check(9)
	return append(instructions,
		BPFInstruction{Op: 0x30, K: base + 6},               // ldb [next header]
		BPFInstruction{Op: 0x15, Jt: 6, K: 17},              // jeq #UDP -> accept
		BPFInstruction{Op: 0x15, Jt: 5, K: ipv6HopByHop},    // jeq #0 -> accept
		BPFInstruction{Op: 0x15, Jt: 4, K: ipv6Routing},     // jeq #43 -> accept
		BPFInstruction{Op: 0x15, Jt: 3, K: ipv6DestOptions}, // jeq #60 -> accept
		BPFInstruction{Op: 0x15, Jf: 3, K: ipv6Fragment},    // jeq #44, else reject
		BPFInstruction{Op: 0x30, K: base + ipv6HeaderLen},   // ldb [fragment next header]
		BPFInstruction{Op: 0x15, Jf: 1, K: 17},              // jeq #UDP
		BPFInstruction{Op: 0x6, K: 0x00040000},              // accept
		BPFInstruction{Op: 0x6, K: 0},                       // reject
	)
}
