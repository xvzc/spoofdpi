// Package capture opens raw packet capture handles and parses captured
// packets.
package capture

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Handle is a common interface for both afpacket (Linux) and pcap (Others)
type Handle interface {
	// ReadPacketData reads the next packet from the wire.
	ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error)

	SetBPFRawInstructionFilter(filters []BPFInstruction) error

	ClearBPF() error

	LinkType() layers.LinkType

	// Close closes the handle.
	Close()
}

type BPFInstruction struct {
	Op uint16
	Jt uint8
	Jf uint8
	K  uint32
}
