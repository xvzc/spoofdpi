package capture

import (
	"errors"
	"fmt"
	"math"
	"net"

	"github.com/google/gopacket/layers"
	"github.com/xvzc/spoofdpi/internal/netutil"
)

// ErrUnsupportedLinkType is returned by the capture filters for a link
// type they cannot locate the IP header on.
var ErrUnsupportedLinkType = errors.New("unsupported link type")

// DLT numbers pcap reports that gopacket names differently or not at
// all: DLT_RAW is 12 on BSD but 101 elsewhere, and 50 is PPP in HDLC-like
// framing.
const (
	dltBSDRaw  layers.LinkType = 12
	dltPPPHDLC layers.LinkType = 50
)

// normalizeLinkType maps the link types pcap reports under another number
// to the ones gopacket and the filters know: Raw and PPP.
func normalizeLinkType(lt layers.LinkType) layers.LinkType {
	switch lt {
	case dltBSDRaw:
		return layers.LinkTypeRaw
	case dltPPPHDLC:
		return layers.LinkTypePPP
	}
	return lt
}

// linuxLinkType returns the link type of the frames an AF_PACKET socket
// bound to a Linux interface with flags and hardwareAddr reads.
//
// Loopback frames carry a fake 14-byte Ethernet header (ARPHRD_LOOPBACK),
// although the all-zero address of lo leaves hardwareAddr empty. Other
// links without a hardware address, such as TUN devices, and
// point-to-point links, such as VPN tunnels, carry raw IP.
func linuxLinkType(flags net.Flags, hardwareAddr net.HardwareAddr) layers.LinkType {
	if flags&net.FlagLoopback != 0 {
		return layers.LinkTypeEthernet
	}
	if len(hardwareAddr) == 0 || flags&net.FlagPointToPoint != 0 {
		return layers.LinkTypeRaw
	}
	return layers.LinkTypeEthernet
}

// linkLayout is where the IP header is on a link, and the BPF
// instructions that check its version.
type linkLayout struct {
	// base is the offset of the IP header.
	base uint32
	// ipv4Check and ipv6Check return instructions that load and test what
	// marks the frame as IPv4 or IPv6, whose last one jumps rejectJf
	// instructions forward on a mismatch and falls through otherwise.
	ipv4Check, ipv6Check func(rejectJf uint8) []BPFInstruction
}

// EtherTypes of IPv4 and IPv6.
const (
	etherTypeIPv4 = 0x0800
	etherTypeIPv6 = 0x86dd
)

// etherTypeCheck tests that the EtherType is etherType.
func etherTypeCheck(etherType uint32) func(uint8) []BPFInstruction {
	return func(rejectJf uint8) []BPFInstruction {
		return []BPFInstruction{
			{Op: 0x28, K: 12},                      // ldh [12]
			{Op: 0x15, Jf: rejectJf, K: etherType}, // jeq #etherType
		}
	}
}

// versionCheck tests that the IP version nibble at base is version.
// Without it the accumulator is 0 and the check always fails, silently
// dropping every packet.
func versionCheck(base, version uint32) func(uint8) []BPFInstruction {
	return func(rejectJf uint8) []BPFInstruction {
		return []BPFInstruction{
			{Op: 0x30, K: base},                       // ldb [base]
			{Op: 0x54, K: 0xf0},                       // and #0xf0
			{Op: 0x15, Jf: rejectJf, K: version << 4}, // jeq #version<<4
		}
	}
}

// PPP protocol numbers of IPv4 and IPv6.
const (
	pppProtocolIPv4 = 0x0021
	pppProtocolIPv6 = 0x0057
)

// pppProtocolCheck tests that the PPP protocol field at protoOffset is
// protocol.
func pppProtocolCheck(protoOffset, protocol uint32) func(uint8) []BPFInstruction {
	return func(rejectJf uint8) []BPFInstruction {
		return []BPFInstruction{
			{Op: 0x28, K: protoOffset},            // ldh [protoOffset]
			{Op: 0x15, Jf: rejectJf, K: protocol}, // jeq #protocol
		}
	}
}

// pppHDLCMarker is the address and control bytes that start a PPP frame
// with HDLC-like framing.
const pppHDLCMarker = 0xff03

// linkLayouts returns the layouts a frame of link type lt can have: one,
// except for PPP, whose frames may or may not start with the HDLC address
// and control bytes. The layout for frames with them comes first.
func linkLayouts(lt layers.LinkType) ([]linkLayout, error) {
	switch lt {
	case layers.LinkTypeEthernet:
		return []linkLayout{{
			base:      14,
			ipv4Check: etherTypeCheck(etherTypeIPv4),
			ipv6Check: etherTypeCheck(etherTypeIPv6),
		}}, nil
	case layers.LinkTypeNull, layers.LinkTypeLoop:
		return []linkLayout{{
			base:      4,
			ipv4Check: versionCheck(4, 4),
			ipv6Check: versionCheck(4, 6),
		}}, nil
	case layers.LinkTypeRaw:
		return []linkLayout{{
			base:      0,
			ipv4Check: versionCheck(0, 4),
			ipv6Check: versionCheck(0, 6),
		}}, nil
	case layers.LinkTypePPP:
		return []linkLayout{
			{
				base:      4,
				ipv4Check: pppProtocolCheck(2, pppProtocolIPv4),
				ipv6Check: pppProtocolCheck(2, pppProtocolIPv6),
			},
			{
				base:      2,
				ipv4Check: pppProtocolCheck(0, pppProtocolIPv4),
				ipv6Check: pppProtocolCheck(0, pppProtocolIPv6),
			},
		}, nil
	}
	return nil, fmt.Errorf("%w: %d", ErrUnsupportedLinkType, lt)
}

// buildForLink returns the program build makes for the layout of link type
// lt. For PPP, it makes one for each framing and starts with a check of
// the HDLC marker that selects between them. build must return a program
// that ends in a return. The marker check jumps over the HDLC framing's
// program with an 8-bit offset, so it returns an error when that program
// has more than 255 instructions.
func buildForLink(
	lt layers.LinkType,
	build func(linkLayout) []BPFInstruction,
) ([]BPFInstruction, error) {
	layouts, err := linkLayouts(lt)
	if err != nil {
		return nil, err
	}
	if len(layouts) == 1 {
		return build(layouts[0]), nil
	}

	hdlc, plain := build(layouts[0]), build(layouts[1])
	if len(hdlc) > math.MaxUint8 {
		return nil, fmt.Errorf(
			"PPP HDLC filter has %d instructions, more than a BPF jump can skip (%d)",
			len(hdlc), math.MaxUint8,
		)
	}
	prog := []BPFInstruction{
		{Op: 0x28, K: 0}, // ldh [0]
		{Op: 0x15, Jf: uint8(len(hdlc)), K: pppHDLCMarker},
	}
	return append(append(prog, hdlc...), plain...), nil
}

// ErrNoFamily is returned by the capture filters for an empty set of
// address families.
var ErrNoFamily = errors.New("no address family to capture")

// familyProgram returns a build function for buildForLink that joins the
// IPv4 and IPv6 branches of the families in fams, IPv4 first. Each branch
// starts with its family check and ends with a reject. ipv4 jumps from its
// check past that reject to the IPv6 branch when nextBranch is set.
func familyProgram(
	fams netutil.FamilySet,
	ipv4 func(l linkLayout, nextBranch bool) []BPFInstruction,
	ipv6 func(l linkLayout) []BPFInstruction,
) (func(linkLayout) []BPFInstruction, error) {
	if !fams.Has(netutil.FamilyV4) && !fams.Has(netutil.FamilyV6) {
		return nil, ErrNoFamily
	}
	return func(l linkLayout) []BPFInstruction {
		var prog []BPFInstruction
		if fams.Has(netutil.FamilyV4) {
			prog = ipv4(l, fams.Has(netutil.FamilyV6))
		}
		if fams.Has(netutil.FamilyV6) {
			prog = append(prog, ipv6(l)...)
		}
		return prog
	}, nil
}

// IPv6 next header values the filters look at.
const (
	ipv6HopByHop    = 0
	ipv6Routing     = 43
	ipv6Fragment    = 44
	ipv6DestOptions = 60
	// ipv6HeaderLen is the length of the fixed IPv6 header.
	ipv6HeaderLen = 40
)
