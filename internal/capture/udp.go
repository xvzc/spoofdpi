package capture

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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

// UDPFilter returns a BPF program for "ip and udp" on the given link type.
// It supports Ethernet, Null (Loopback/VPN), and Raw IP link types.
func UDPFilter(linkType layers.LinkType) []BPFInstruction {
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
