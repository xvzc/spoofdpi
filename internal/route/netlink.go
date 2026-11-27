package route

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"syscall"

	"github.com/xvzc/spoofdpi/internal/netutil"
)

// Linux netlink and rtnetlink constants (<linux/netlink.h>,
// <linux/rtnetlink.h>, <asm-generic/errno.h>). They are defined here
// rather than taken from x/sys/unix so that the encoder and parser build
// and are tested on every OS. A Linux-only test checks them against unix.
const (
	nlmsgHdrLen  = 16
	nlmsgError   = 0x2
	nlmsgDone    = 0x3
	nlmFRequest  = 0x1
	nlmFDump     = 0x300
	nlmFDumpIntr = 0x10
	nlaTypeMask  = 0x3fff

	rtmNewRoute     = 24
	rtmGetRoute     = 26
	rtmsgLen        = 12
	rtmFLookupTable = 0x1000

	rtaDst       = 1
	rtaOif       = 4
	rtaGateway   = 5
	rtaPrefsrc   = 7
	rtaMultipath = 9
	rtaTable     = 15
	rtaVia       = 18

	rtnUnicast     = 1
	rtnBlackhole   = 6
	rtnUnreachable = 7
	rtnProhibit    = 8
	rtnThrow       = 9

	rtnhFDead     = 0x1
	rtnhFLinkdown = 0x10

	linuxAFInet  = 2
	linuxAFInet6 = 10

	linuxEACCES       = 13
	linuxEINVAL       = 22
	linuxENETUNREACH  = 101
	linuxEHOSTUNREACH = 113
)

// netlinkMessage is one netlink message: its header fields and payload.
type netlinkMessage struct {
	typ   uint16
	flags uint16
	seq   uint32
	pid   uint32
	data  []byte
}

// nlAlign rounds n up to the netlink alignment of 4 bytes.
func nlAlign(n int) int { return (n + 3) &^ 3 }

// appendNetlinkHeader appends a netlink header for a message whose payload
// is payloadLen bytes long.
func appendNetlinkHeader(
	b []byte,
	payloadLen int,
	typ, flags uint16,
	seq uint32,
) []byte {
	b = binary.NativeEndian.AppendUint32(b, uint32(nlmsgHdrLen+payloadLen))
	b = binary.NativeEndian.AppendUint16(b, typ)
	b = binary.NativeEndian.AppendUint16(b, flags)
	b = binary.NativeEndian.AppendUint32(b, seq)
	// The kernel fills in the sender's port id.
	return binary.NativeEndian.AppendUint32(b, 0)
}

// appendAttr appends a route attribute of typ with val, padded.
func appendAttr(b []byte, typ uint16, val []byte) []byte {
	b = binary.NativeEndian.AppendUint16(b, uint16(4+len(val)))
	b = binary.NativeEndian.AppendUint16(b, typ)
	b = append(b, val...)
	return append(b, make([]byte, nlAlign(len(val))-len(val))...)
}

// linuxFamily returns the Linux address family of fam.
func linuxFamily(fam netutil.Family) uint8 {
	if fam == netutil.FamilyV6 {
		return linuxAFInet6
	}
	return linuxAFInet
}

// encodeRouteGet returns an RTM_GETROUTE request for the route to dst,
// resolved the way a socket connected to dst would be (no dump), with the
// table of the matching route reported (RTM_F_LOOKUP_TABLE).
func encodeRouteGet(seq uint32, dst netip.Addr) []byte {
	addr := dst.AsSlice()
	attrs := appendAttr(nil, rtaDst, addr)

	b := appendNetlinkHeader(nil, rtmsgLen+len(attrs), rtmGetRoute, nlmFRequest, seq)
	b = append(b,
		linuxFamily(familyOf(dst)), // rtm_family
		uint8(len(addr)*8),         // rtm_dst_len
		0, 0, 0, 0, 0, 0,           // src_len, tos, table, protocol, scope, type
	)
	b = binary.NativeEndian.AppendUint32(b, rtmFLookupTable)
	return append(b, attrs...)
}

// encodeRouteDump returns an RTM_GETROUTE request that dumps the routes of
// fam in every table.
func encodeRouteDump(seq uint32, fam netutil.Family) []byte {
	b := appendNetlinkHeader(nil, rtmsgLen, rtmGetRoute, nlmFRequest|nlmFDump, seq)
	b = append(b, linuxFamily(fam))
	return append(b, make([]byte, rtmsgLen-1)...)
}

// parseNetlinkMessages splits b, the bytes of one netlink receive, into
// messages. The payloads alias b.
func parseNetlinkMessages(b []byte) ([]netlinkMessage, error) {
	var msgs []netlinkMessage
	for len(b) >= nlmsgHdrLen {
		l := int(binary.NativeEndian.Uint32(b[0:4]))
		if l < nlmsgHdrLen || l > len(b) {
			return nil, fmt.Errorf("netlink: bad message length %d of %d", l, len(b))
		}
		msgs = append(msgs, netlinkMessage{
			typ:   binary.NativeEndian.Uint16(b[4:6]),
			flags: binary.NativeEndian.Uint16(b[6:8]),
			seq:   binary.NativeEndian.Uint32(b[8:12]),
			pid:   binary.NativeEndian.Uint32(b[12:16]),
			data:  b[nlmsgHdrLen:l],
		})
		b = b[min(nlAlign(l), len(b)):]
	}
	return msgs, nil
}

// netlinkMessageError returns the error that m, an NLMSG_ERROR message,
// carries as a syscall.Errno with Linux numbering, or nil for an
// acknowledgement.
func netlinkMessageError(m netlinkMessage) error {
	if len(m.data) < 4 {
		return errors.New("netlink: short error message")
	}
	code := int32(binary.NativeEndian.Uint32(m.data[0:4]))
	if code == 0 {
		return nil
	}
	return fmt.Errorf("netlink: %w", syscall.Errno(-code))
}

// errNetlinkDumpInterrupted is returned by collectReply when the kernel
// marks a dump as interrupted (NLM_F_DUMP_INTR): the table changed while
// it was dumped, so the dump may be inconsistent.
var errNetlinkDumpInterrupted = errors.New("netlink: dump interrupted")

// netlinkDoneError returns the error that m, an NLMSG_DONE message,
// carries: a negative errno in its first 4 bytes, or nil for success.
func netlinkDoneError(m netlinkMessage) error {
	if len(m.data) < 4 {
		return errors.New("netlink: short done message")
	}
	code := int32(binary.NativeEndian.Uint32(m.data[0:4]))
	if code < 0 {
		return fmt.Errorf("netlink: dump: %w", syscall.Errno(-code))
	}
	return nil
}

// isNoRouteErrno reports whether err is the errno the kernel answers the
// RTM_GETROUTE lookup of dst with when it has no route: no matching route
// (ENETUNREACH), an unreachable route (EHOSTUNREACH), a prohibit route
// (EACCES), and for IPv4 a blackhole route (EINVAL). EINVAL also means a
// malformed request, so it stays an error for IPv6 lookups and for every
// other request.
func isNoRouteErrno(err error, dst netip.Addr) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	switch errno {
	case linuxENETUNREACH, linuxEHOSTUNREACH, linuxEACCES:
		return true
	case linuxEINVAL:
		return dst.Is4()
	default:
		return false
	}
}

// collectReply adds the messages of msgs that answer the request of seq
// from port pid to reply. A request that is not a dump is answered by its
// first message; a dump ends with NLMSG_DONE, which carries the dump's
// errno. done reports whether the answer is complete. An NLMSG_ERROR ends
// it with its error, and a message of an interrupted dump with
// errNetlinkDumpInterrupted. The payloads in reply are copies.
func collectReply(
	reply, msgs []netlinkMessage,
	seq, pid uint32,
	dump bool,
) (_ []netlinkMessage, done bool, err error) {
	for _, m := range msgs {
		if m.seq != seq || m.pid != pid {
			continue
		}
		if dump && m.flags&nlmFDumpIntr != 0 {
			return reply, true, errNetlinkDumpInterrupted
		}
		switch m.typ {
		case nlmsgError:
			return reply, true, netlinkMessageError(m)
		case nlmsgDone:
			return reply, true, netlinkDoneError(m)
		}
		m.data = slices.Clone(m.data)
		reply = append(reply, m)
		if !dump {
			return reply, true, nil
		}
	}
	return reply, false, nil
}

// walkAttrs calls fn for each route attribute in b with its type, without
// the nested and byte-order flags, and its value.
func walkAttrs(b []byte, fn func(typ uint16, val []byte)) error {
	for len(b) >= 4 {
		l := int(binary.NativeEndian.Uint16(b[0:2]))
		if l < 4 || l > len(b) {
			return fmt.Errorf("netlink: bad attribute length %d of %d", l, len(b))
		}
		fn(binary.NativeEndian.Uint16(b[2:4])&nlaTypeMask, b[4:l])
		b = b[min(nlAlign(l), len(b)):]
	}
	return nil
}

// netlinkRoute is a decoded RTM_NEWROUTE message.
type netlinkRoute struct {
	family   uint8
	dstLen   uint8
	protocol uint8
	scope    uint8
	typ      uint8
	// flags is rtm_flags, which carries the RTNH_F_* flags of a route
	// with a single next hop.
	flags   uint32
	table   int
	oif     int
	dst     netip.Addr
	gateway netip.Addr
	prefsrc netip.Addr
	// via reports an RTA_VIA next hop, a gateway of another family
	// (RFC 5549).
	via bool
	// nexthopOifs are the output interfaces of the live next hops of an
	// RTA_MULTIPATH route.
	nexthopOifs []int
}

// parseNetlinkRoute decodes data, the payload of an RTM_NEWROUTE message.
// RTA_TABLE, when present, overrides the 8-bit rtm_table.
func parseNetlinkRoute(data []byte) (netlinkRoute, error) {
	if len(data) < rtmsgLen {
		return netlinkRoute{}, errors.New("netlink: short route message")
	}
	r := netlinkRoute{
		family:   data[0],
		dstLen:   data[1],
		table:    int(data[4]),
		protocol: data[5],
		scope:    data[6],
		typ:      data[7],
		flags:    binary.NativeEndian.Uint32(data[8:12]),
	}
	err := walkAttrs(data[rtmsgLen:], func(typ uint16, val []byte) {
		switch typ {
		case rtaDst:
			r.dst, _ = netip.AddrFromSlice(val)
		case rtaOif:
			if len(val) >= 4 {
				r.oif = int(binary.NativeEndian.Uint32(val))
			}
		case rtaGateway:
			r.gateway, _ = netip.AddrFromSlice(val)
		case rtaPrefsrc:
			r.prefsrc, _ = netip.AddrFromSlice(val)
		case rtaTable:
			if len(val) >= 4 {
				r.table = int(binary.NativeEndian.Uint32(val))
			}
		case rtaVia:
			r.via = true
		case rtaMultipath:
			r.nexthopOifs = parseNexthopOifs(val)
		}
	})
	return r, err
}

// parseNexthopOifs returns the interface indexes of the rtnexthop entries
// in b, the value of RTA_MULTIPATH, that are neither dead nor link-down.
// Each entry is a 2-byte length, flags, hops, a 4-byte ifindex and the
// entry's own attributes.
func parseNexthopOifs(b []byte) []int {
	var oifs []int
	for len(b) >= 8 {
		l := int(binary.NativeEndian.Uint16(b[0:2]))
		if l < 8 || l > len(b) {
			break
		}
		if !isDeadNexthop(uint32(b[2])) {
			oifs = append(oifs, int(int32(binary.NativeEndian.Uint32(b[4:8]))))
		}
		b = b[min(nlAlign(l), len(b)):]
	}
	return oifs
}

// isDeadNexthop reports whether the RTNH_F_* flags mark a next hop as dead
// or its link as down, so that the kernel does not route through it.
func isDeadNexthop(flags uint32) bool {
	return flags&(rtnhFDead|rtnhFLinkdown) != 0
}

// kernelRouteFromNetlink reads the route to dst from reply, the answer to
// encodeRouteGet. The kernel usually answers a lookup that hits an
// unreachable, prohibit or (IPv4) blackhole route with an errno, which
// isNoRouteErrno sorts out before this. A reply whose route is of such a
// dropping type still counts as no route here; other types than unicast,
// such as local or broadcast, are errors.
func kernelRouteFromNetlink(
	reply []netlinkMessage,
	dst netip.Addr,
) (kernelRoute, error) {
	if len(reply) != 1 || reply[0].typ != rtmNewRoute {
		return kernelRoute{}, fmt.Errorf("route lookup %s: no route in the reply", dst)
	}
	r, err := parseNetlinkRoute(reply[0].data)
	if err != nil {
		return kernelRoute{}, fmt.Errorf("route lookup %s: %w", dst, err)
	}
	if r.family != linuxFamily(familyOf(dst)) {
		return kernelRoute{}, fmt.Errorf(
			"route lookup %s: reply of address family %d", dst, r.family,
		)
	}
	switch r.typ {
	case rtnUnicast:
	case rtnBlackhole, rtnUnreachable, rtnProhibit, rtnThrow:
		return kernelRoute{}, errNoRoute(dst)
	default:
		return kernelRoute{}, fmt.Errorf(
			"route lookup %s: route of type %d is not unicast", dst, r.typ,
		)
	}
	if r.via {
		return kernelRoute{}, fmt.Errorf(
			"route lookup %s: next hops of another address family (RTA_VIA) "+
				"are not supported",
			dst,
		)
	}
	if r.oif <= 0 {
		return kernelRoute{}, fmt.Errorf("route lookup %s: no output interface", dst)
	}
	return kernelRoute{
		ifIndex: r.oif,
		gateway: r.gateway,
		src:     r.prefsrc,
		table:   r.table,
	}, nil
}

// defaultRouteOifs returns the output interfaces of the unicast default
// routes of fam in reply, a route dump, in dump order and without
// duplicates. The dump covers every table, so a default that a VPN left
// in the main table while it routes through its own table counts. Dead
// and link-down routes and next hops are skipped.
func defaultRouteOifs(reply []netlinkMessage, fam netutil.Family) ([]int, error) {
	var oifs []int
	add := func(oif int) {
		if oif > 0 && !slices.Contains(oifs, oif) {
			oifs = append(oifs, oif)
		}
	}
	for _, m := range reply {
		if m.typ != rtmNewRoute {
			continue
		}
		r, err := parseNetlinkRoute(m.data)
		if err != nil {
			return nil, err
		}
		if r.family != linuxFamily(fam) || r.dstLen != 0 || r.typ != rtnUnicast {
			continue
		}
		if !isDeadNexthop(r.flags) {
			add(r.oif)
		}
		for _, oif := range r.nexthopOifs {
			add(oif)
		}
	}
	return oifs, nil
}

// rtmFFibMatch is RTM_F_FIB_MATCH (Linux 4.13+): a lookup with it reports
// the routing table entry that matched, with its prefix length in
// rtm_dst_len, instead of the route resolved for the destination. Older
// kernels ignore it and report a dst_len of the full address length.
const rtmFFibMatch = 0x2000

// encodeRouteFIBMatch returns an RTM_GETROUTE request for the routing
// table entry that the kernel matches for dst (RTM_F_FIB_MATCH), resolved
// the way a socket connected to dst would be (no dump).
func encodeRouteFIBMatch(seq uint32, dst netip.Addr) []byte {
	addr := dst.AsSlice()
	attrs := appendAttr(nil, rtaDst, addr)

	b := appendNetlinkHeader(nil, rtmsgLen+len(attrs), rtmGetRoute, nlmFRequest, seq)
	b = append(b,
		linuxFamily(familyOf(dst)), // rtm_family
		uint8(len(addr)*8),         // rtm_dst_len
		0, 0, 0, 0, 0, 0,           // src_len, tos, table, protocol, scope, type
	)
	b = binary.NativeEndian.AppendUint32(b, rtmFFibMatch)
	return append(b, attrs...)
}

// prefixFromNetlink reads the prefix of the route that matched dst from
// reply, the answer to encodeRouteFIBMatch. A route of another type than
// unicast, such as blackhole, unreachable or local, counts as no route.
func prefixFromNetlink(reply []netlinkMessage, dst netip.Addr) (netip.Prefix, error) {
	if len(reply) != 1 || reply[0].typ != rtmNewRoute {
		return netip.Prefix{}, fmt.Errorf("route lookup %s: no route in the reply", dst)
	}
	r, err := parseNetlinkRoute(reply[0].data)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("route lookup %s: %w", dst, err)
	}
	if r.family != linuxFamily(familyOf(dst)) {
		return netip.Prefix{}, fmt.Errorf(
			"route lookup %s: reply of address family %d", dst, r.family,
		)
	}
	if r.typ != rtnUnicast {
		return netip.Prefix{}, errNoRoute(dst)
	}
	if int(r.dstLen) > dst.BitLen() {
		return netip.Prefix{}, fmt.Errorf(
			"route lookup %s: prefix length %d is out of range", dst, r.dstLen,
		)
	}
	return netip.PrefixFrom(dst, int(r.dstLen)).Masked(), nil
}
