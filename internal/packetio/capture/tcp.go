package capture

import (
	"encoding/binary"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// TCPSegment is a captured IPv4 TCP segment.
type TCPSegment struct {
	Src, Dst           net.IP
	SrcPort, DstPort   uint16
	Seq, Ack           uint32
	SYN, ACK, RST, FIN bool
	PayloadLen         int
	// TTL is the IPv4 TTL the packet was captured with: the one it left
	// with, for a packet this host sends.
	TTL uint8
	// SACK are the blocks of the SACK option, as [left, right) sequence
	// numbers.
	SACK [][2]uint32
}

// ParseTCPSegment returns the TCP segment carried by p. ok is false if p
// is not an IPv4 TCP packet.
func ParseTCPSegment(p gopacket.Packet) (seg TCPSegment, ok bool) {
	ipLayer, _ := p.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	tcp, _ := p.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if ipLayer == nil || tcp == nil {
		return TCPSegment{}, false
	}
	seg = TCPSegment{
		Src:        ipLayer.SrcIP,
		Dst:        ipLayer.DstIP,
		SrcPort:    uint16(tcp.SrcPort),
		DstPort:    uint16(tcp.DstPort),
		Seq:        tcp.Seq,
		Ack:        tcp.Ack,
		SYN:        tcp.SYN,
		ACK:        tcp.ACK,
		RST:        tcp.RST,
		FIN:        tcp.FIN,
		PayloadLen: len(tcp.Payload),
		TTL:        ipLayer.TTL,
	}
	for _, opt := range tcp.Options {
		if opt.OptionType != layers.TCPOptionKindSACK {
			continue
		}
		for d := opt.OptionData; len(d) >= 8; d = d[8:] {
			seg.SACK = append(seg.SACK, [2]uint32{
				binary.BigEndian.Uint32(d[:4]), binary.BigEndian.Uint32(d[4:8]),
			})
		}
	}
	return seg, true
}

// maxFilterHosts is the most hosts TCPHostFilter checks for: a BPF jump
// skips at most 255 instructions, and each host takes two.
const maxFilterHosts = 100

// TCPHostFilter returns a BPF program that accepts unfragmented IPv4 TCP
// packets from or to any of hosts, on the given link type. With more than
// 100 hosts, it accepts every unfragmented IPv4 TCP packet. It supports
// Ethernet, Null/Loop (loopback and VPN), Raw IP, and PPP, and returns
// ErrUnsupportedLinkType for any other.
func TCPHostFilter(linkType layers.LinkType, hosts []net.IP) ([]BPFInstruction, error) {
	return buildForLink(linkType, func(l linkLayout) []BPFInstruction {
		return tcpHostProgram(l, hosts)
	})
}

// tcpHostProgram is the TCP host filter for the frames of layout l.
func tcpHostProgram(l linkLayout, hosts []net.IP) []BPFInstruction {
	base := l.base

	checkHosts := len(hosts) <= maxFilterHosts
	var addrs []uint32
	if checkHosts {
		for _, h := range hosts {
			if ip4 := h.To4(); ip4 != nil {
				addrs = append(addrs, binary.BigEndian.Uint32(ip4))
			}
		}
	}

	// Jumps name their targets with these labels until the program is
	// laid out.
	const next, accept, reject = 0, -1, -2
	type jumpAt struct{ at, jt, jf int }
	var prog []BPFInstruction
	var jumps []jumpAt
	emit := func(op uint16, k uint32) int {
		prog = append(prog, BPFInstruction{Op: op, K: k})
		return len(prog) - 1
	}
	jump := func(op uint16, k uint32, jt, jf int) {
		jumps = append(jumps, jumpAt{at: emit(op, k), jt: jt, jf: jf})
	}

	// IPv4: its last instruction jumps to reject on a mismatch.
	prog = append(prog, l.ipv4Check(0)...)
	jumps = append(jumps, jumpAt{at: len(prog) - 1, jt: next, jf: reject})
	emit(0x30, base+9) // ldb [protocol]
	jump(0x15, 6, next, reject)
	emit(0x28, base+6) // ldh [flags and fragment offset]
	jump(0x45, 0x1fff, reject, next)

	// Each check falls through to the next instruction when it does not
	// jump, so the last check falls through to reject, or, without host
	// checks, to accept.
	var acceptAt, rejectAt int
	if checkHosts {
		for _, off := range []uint32{base + 12, base + 16} { // source, destination
			emit(0x20, off) // ld [address]
			for _, a := range addrs {
				jump(0x15, a, accept, next)
			}
		}
		rejectAt = emit(0x06, 0)
		acceptAt = emit(0x06, 0x00040000)
	} else {
		acceptAt = emit(0x06, 0x00040000)
		rejectAt = emit(0x06, 0)
	}

	resolve := func(at, label int) uint8 {
		switch label {
		case accept:
			return uint8(acceptAt - at - 1)
		case reject:
			return uint8(rejectAt - at - 1)
		}
		return 0
	}
	for _, j := range jumps {
		prog[j.at].Jt = resolve(j.at, j.jt)
		prog[j.at].Jf = resolve(j.at, j.jf)
	}
	return prog
}
