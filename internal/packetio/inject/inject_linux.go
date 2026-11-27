//go:build linux

package inject

import "golang.org/x/net/ipv4"

// What differs on Linux:
//
//   - ipv4.Header.Marshal writes ip_len and ip_off in network order, as
//     Linux expects. With IP_HDRINCL the kernel always rewrites tot_len
//     and the header checksum, and fills the ID when it is 0
//     (raw_send_hdrinc in net/ipv4/raw.c). Protocol 255 (IPPROTO_RAW)
//     already implies IP_HDRINCL, and such a socket receives nothing.
//   - IPV6_CHECKSUM is off by default on IPv6 raw sockets other than
//     ICMPv6 and MH (rawv6_init_sk in net/ipv6/raw.c), as on BSD. Unlike
//     on BSD, the TCP and UDP sockets receive copies of incoming packets
//     of their protocol, which the small receive buffer drops.
//   - The route of a header-included IPv4 packet is looked up with the
//     socket's source, not the one in the header (raw_sendmsg in
//     net/ipv4/raw.c), so ipv4Control passes the header's source. See
//     ipv4Control for why.

// ipv4Control returns the ancillary data that p is sent with: IP_PKTINFO
// with p.Src as ipi_spec_dst and no interface.
//
// raw_sendmsg looks the route up with the source of IP_PKTINFO, or with
// the socket's bound source, 0.0.0.0, without it. Source-based policy
// rules then match the fake as they match the real connection, such as
// TUN mode's "ip rule from <physical source> lookup main", which sends the
// fake out by the main table's routes, as the real connection goes.
//
// In TUN mode the socket is also bound to the physical interface with
// SO_BINDTODEVICE and marked with SO_MARK. The mark also skips TUN mode's
// capture rule, "not fwmark <mark> lookup <capture table>", whose default
// route leads into the TUN, so a fake that no source-based rule matches
// still reaches the main table's routes.
//
// The interface index stays 0, which keeps the socket's bound interface
// (ip_cmsg_send in net/ipv4/ip_sockglue.c). Any source is accepted, since
// header-included sockets route with FLOWI_FLAG_ANYSRC.
func ipv4Control(p Packet) *ipv4.ControlMessage {
	return &ipv4.ControlMessage{Src: p.Src.AsSlice()}
}
