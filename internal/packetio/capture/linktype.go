package capture

import (
	"errors"
	"fmt"
	"math"

	"github.com/google/gopacket/layers"
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

// linkLayout is where the IP header is on a link, and the BPF
// instructions that check it is IPv4.
type linkLayout struct {
	// base is the offset of the IP header.
	base uint32
	// ipv4Check returns instructions that load and test what marks the
	// frame as IPv4, whose last one jumps rejectJf instructions forward on
	// a mismatch and falls through otherwise.
	ipv4Check func(rejectJf uint8) []BPFInstruction
}

// etherTypeCheck tests that the EtherType is IPv4.
func etherTypeCheck(rejectJf uint8) []BPFInstruction {
	return []BPFInstruction{
		{Op: 0x28, K: 12},                   // ldh [12]
		{Op: 0x15, Jf: rejectJf, K: 0x0800}, // jeq #0x0800
	}
}

// versionCheck tests that the IP version nibble at base is 4. Without it
// the accumulator is 0 and the check always fails, silently dropping every
// packet.
func versionCheck(base uint32) func(uint8) []BPFInstruction {
	return func(rejectJf uint8) []BPFInstruction {
		return []BPFInstruction{
			{Op: 0x30, K: base},               // ldb [base]
			{Op: 0x54, K: 0xf0},               // and #0xf0
			{Op: 0x15, Jf: rejectJf, K: 0x40}, // jeq #0x40
		}
	}
}

// pppProtocolCheck tests that the PPP protocol field at protoOffset is
// IPv4 (0x0021).
func pppProtocolCheck(protoOffset uint32) func(uint8) []BPFInstruction {
	return func(rejectJf uint8) []BPFInstruction {
		return []BPFInstruction{
			{Op: 0x28, K: protoOffset},          // ldh [protoOffset]
			{Op: 0x15, Jf: rejectJf, K: 0x0021}, // jeq #0x0021
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
		return []linkLayout{{base: 14, ipv4Check: etherTypeCheck}}, nil
	case layers.LinkTypeNull, layers.LinkTypeLoop:
		return []linkLayout{{base: 4, ipv4Check: versionCheck(4)}}, nil
	case layers.LinkTypeRaw:
		return []linkLayout{{base: 0, ipv4Check: versionCheck(0)}}, nil
	case layers.LinkTypePPP:
		return []linkLayout{
			{base: 4, ipv4Check: pppProtocolCheck(2)},
			{base: 2, ipv4Check: pppProtocolCheck(0)},
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
