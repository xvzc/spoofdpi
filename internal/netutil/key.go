package netutil

import (
	"encoding/binary"
	"fmt"
	"net"
)

/*
`isIPv4Mapped` checks if the 16-byte array contains an IPv4-mapped IPv6 address.

Note: While net.IP.To4() is generally preferred for standard IP checks,
this function is strictly optimized for IPKey/NATKey types to avoid
unnecessary allocations and overhead in high-performance paths.
DO NOT use this function in other contexts.
*/
func isIPv4Mapped(ip [16]byte) bool {
	// IPv4-mapped IPv6 address has the prefix 0:0:0:0:0:FFFF
	for i := 0; i < 10; i++ {
		if ip[i] != 0 {
			return false
		}
	}
	if ip[10] != 0xff || ip[11] != 0xff {
		return false
	}
	return true
}

// NATKey represents a 4-tuple (SrcIP, SrcPort, DstIP, DstPort) for zero-allocation NAT session mapping
type NATKey struct {
	SrcIP   [16]byte
	SrcPort uint16
	DstIP   [16]byte
	DstPort uint16
}

// String returns the string representation of the session key.
// Only used for debugging / logging.
func (k NATKey) String() string {
	var srcIP, dstIP net.IP

	// Check if IPv4-mapped IPv6
	if isIPv4Mapped(k.SrcIP) {
		srcIP = net.IP(k.SrcIP[12:16])
	} else {
		srcIP = net.IP(k.SrcIP[:])
	}

	if isIPv4Mapped(k.DstIP) {
		dstIP = net.IP(k.DstIP[12:16])
	} else {
		dstIP = net.IP(k.DstIP[:])
	}

	return fmt.Sprintf("%v:%d>%v:%d", srcIP, k.SrcPort, dstIP, k.DstPort)
}

// IPKey represents an IP address for zero-allocation cache mapping
type IPKey [16]byte

// String returns the string representation of the IPKey.
func (k IPKey) String() string {
	var srcIP net.IP
	if isIPv4Mapped(k) {
		srcIP = net.IP(k[12:16])
	} else {
		srcIP = net.IP(k[:])
	}
	return srcIP.String()
}

func (k IPKey) Bytes() []byte { return k[:] }

// NewIPKey zero-alloc constructs an IPKey from net.IP
func NewIPKey(ip net.IP) IPKey {
	var k IPKey
	ip16 := ip.To16()
	if ip16 != nil {
		copy(k[:], ip16)
	}
	return k
}

func (k NATKey) Bytes() []byte {
	var b [36]byte
	copy(b[0:16], k.SrcIP[:])
	binary.BigEndian.PutUint16(b[16:18], k.SrcPort)
	copy(b[18:34], k.DstIP[:])
	binary.BigEndian.PutUint16(b[34:36], k.DstPort)
	return b[:]
}

// NewNATKey zero-alloc constructs a NATKey from two UDPAddr
func NewNATKey(srcIP net.IP, srcPort int, dstIP net.IP, dstPort int) NATKey {
	var k NATKey

	// net.IP is a slice. Let's force it to 16 bytes for comparable struct key
	srcIP16 := srcIP.To16()
	if srcIP16 != nil {
		copy(k.SrcIP[:], srcIP16)
	}

	dstIP16 := dstIP.To16()
	if dstIP16 != nil {
		copy(k.DstIP[:], dstIP16)
	}

	k.SrcPort = uint16(srcPort)
	k.DstPort = uint16(dstPort)

	return k
}
