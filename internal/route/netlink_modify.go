package route

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// Linux constants of the requests that change addresses, links, routes and
// rules (<linux/netlink.h>, <linux/rtnetlink.h>, <linux/if_addr.h>,
// <linux/if.h>); see netlink.go for why they are kept here.
const (
	nlmFAck    = 0x4
	nlmFExcl   = 0x200
	nlmFCreate = 0x400

	rtmNewAddr  = 20
	rtmDelAddr  = 21
	rtmDelRoute = 25

	ifaddrmsgLen = 8
	ifaAddress   = 1
	ifaLocal     = 2

	iffUp = 0x1
)

// InterfaceAddr is an address of a Linux link, as `ip addr add Local/PrefixLen
// peer Peer dev <Index>` sets it.
type InterfaceAddr struct {
	// Index is the interface index of the link.
	Index int
	// Local is the address of the link (IFA_LOCAL).
	Local netip.Addr
	// Peer is the address of the other end of a point-to-point link
	// (IFA_ADDRESS). The zero Addr means none: IFA_ADDRESS is then Local.
	Peer netip.Addr
	// PrefixLen is the prefix length of Peer, or of Local without a peer.
	// ip uses the full address length when none is given.
	PrefixLen int
}

func (a InterfaceAddr) String() string {
	s := fmt.Sprintf("%s/%d", a.Local, a.PrefixLen)
	if a.Peer.IsValid() {
		s = fmt.Sprintf("%s peer %s/%d", a.Local, a.Peer, a.PrefixLen)
	}
	return fmt.Sprintf("%s dev %d", s, a.Index)
}

// appendModifyHeader appends the netlink header of a request that changes
// the kernel's state and asks for an acknowledgement (NLM_F_ACK), so that
// its errno, or 0, comes back as NLMSG_ERROR. create adds NLM_F_CREATE and
// NLM_F_EXCL, so that adding an existing object fails with EEXIST.
func appendModifyHeader(
	b []byte,
	payloadLen int,
	typ uint16,
	seq uint32,
	create bool,
) []byte {
	flags := uint16(nlmFRequest | nlmFAck)
	if create {
		flags |= nlmFCreate | nlmFExcl
	}
	return appendNetlinkHeader(b, payloadLen, typ, flags, seq)
}

// encodeAddrModify returns an RTM_NEWADDR (add) or RTM_DELADDR request for
// a. A delete removes the address of a.Index that matches the local and
// peer addresses and the prefix length.
func encodeAddrModify(seq uint32, a InterfaceAddr, add bool) []byte {
	peer := a.Peer
	if !peer.IsValid() {
		peer = a.Local
	}
	attrs := appendAttr(nil, ifaLocal, a.Local.AsSlice())
	attrs = appendAttr(attrs, ifaAddress, peer.AsSlice())

	typ := uint16(rtmDelAddr)
	if add {
		typ = rtmNewAddr
	}
	b := appendModifyHeader(nil, ifaddrmsgLen+len(attrs), typ, seq, add)
	b = append(b,
		linuxFamily(familyOf(a.Local)), // ifa_family
		uint8(a.PrefixLen),             // ifa_prefixlen
		0, 0,                           // ifa_flags, ifa_scope
	)
	b = binary.NativeEndian.AppendUint32(b, uint32(int32(a.Index)))
	return append(b, attrs...)
}

// encodeLinkSetUp returns an RTM_NEWLINK request that sets the link with
// index up, or down, and changes no other flag.
func encodeLinkSetUp(seq uint32, index int, up bool) []byte {
	var flags uint32
	if up {
		flags = iffUp
	}
	b := appendModifyHeader(nil, ifinfomsgLen, rtmNewLink, seq, false)
	b = append(b, 0, 0, 0, 0) // ifi_family, pad, ifi_type
	b = binary.NativeEndian.AppendUint32(b, uint32(int32(index)))
	b = binary.NativeEndian.AppendUint32(b, flags)
	return binary.NativeEndian.AppendUint32(b, iffUp) // ifi_change
}
