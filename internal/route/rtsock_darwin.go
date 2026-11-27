package route

import (
	"encoding/binary"
	"fmt"
	"net"

	xroute "golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// callerRouteFlags are the flags of TableRoute.Flags that a write keeps.
// The others are the kernel's, such as RTF_LLINFO, which would make it
// read a link gateway as a link-layer address.
const callerRouteFlags = unix.RTF_PROTO1 | unix.RTF_PROTO2 | unix.RTF_PROTO3 |
	unix.RTF_BLACKHOLE | unix.RTF_REJECT | unix.RTF_IFSCOPE

// deleteMatchesGateway is false: darwin finds the route to delete by
// destination, netmask and scope alone.
const deleteMatchesGateway = false

// setRouteSocketFIB does nothing: darwin has a single routing table, and
// checkFIB has refused any other.
func setRouteSocketFIB(int, int) error {
	return nil
}

// fetchRouteDump returns the routing table dump of address family af.
// fib must be 0.
func fetchRouteDump(af, fib int) ([]byte, error) {
	if err := checkFIB(fib); err != nil {
		return nil, err
	}
	return xroute.FetchRIB(af, xroute.RIBTypeRoute, 0)
}

// checkFIB refuses any fib but 0: darwin has no FIBs.
func checkFIB(fib int) error {
	if fib != 0 {
		return fmt.Errorf("fib %d: darwin has no FIBs", fib)
	}
	return nil
}

// linkGateway returns the sockaddr_dl of the interface with index, with
// its name and hardware address, as route(8) sends it for -interface.
func linkGateway(index int) (*xroute.LinkAddr, error) {
	iface, err := net.InterfaceByIndex(index)
	if err != nil {
		return nil, err
	}
	return linkGatewayOf(iface), nil
}

func linkGatewayOf(iface *net.Interface) *xroute.LinkAddr {
	return &xroute.LinkAddr{
		Index: iface.Index,
		Name:  iface.Name,
		Addr:  iface.HardwareAddr,
	}
}

// marshalRouteMessage returns the wire form of m, an RTM_ADD or RTM_DELETE
// with IPv4, IPv6 and link addresses. x/net/route writes a sockaddr_dl
// only as long as its name and address, but darwin's ARP and ND code take
// a link gateway shorter than struct sockaddr_dl as invalid, so a
// sockaddr_dl is written here at least that long, as route(8) sends it.
// Addresses are rounded up to 4 bytes. The message is exactly as long as
// its rtm_msglen, as route(8) sends these writes: the 1024 bytes that
// x/net/route adds after a darwin message (golang.org/issue/22456) are
// for the kernel's RTM_GET reply, which these writes do not read.
func marshalRouteMessage(m *xroute.RouteMessage) ([]byte, error) {
	b := make([]byte, unix.SizeofRtMsghdr)
	var attrs uint32
	for i, a := range m.Addrs {
		var sa []byte
		switch a := a.(type) {
		case nil:
			continue
		case *xroute.Inet4Addr:
			sa = make([]byte, unix.SizeofSockaddrInet4)
			sa[1] = unix.AF_INET
			copy(sa[4:8], a.IP[:])
		case *xroute.Inet6Addr:
			sa = make([]byte, unix.SizeofSockaddrInet6)
			sa[1] = unix.AF_INET6
			copy(sa[8:24], a.IP[:])
			binary.NativeEndian.PutUint32(sa[24:28], uint32(a.ZoneID))
		case *xroute.LinkAddr:
			// sdl_data holds the name, then the address.
			data := append([]byte(a.Name), a.Addr...)
			sa = make([]byte, max(unix.SizeofSockaddrDatalink, 8+len(data)))
			sa[1] = unix.AF_LINK
			binary.NativeEndian.PutUint16(sa[2:4], uint16(a.Index))
			sa[5] = byte(len(a.Name))
			sa[6] = byte(len(a.Addr))
			copy(sa[8:], data)
		default:
			return nil, fmt.Errorf("address %d: unsupported %T", i, a)
		}
		sa[0] = byte(len(sa))
		attrs |= 1 << i
		b = append(b, sa...)
		b = append(b, make([]byte, (4-len(sa)%4)%4)...)
	}
	binary.NativeEndian.PutUint16(b[0:2], uint16(len(b)))
	b[2] = byte(m.Version)
	b[3] = byte(m.Type)
	binary.NativeEndian.PutUint16(b[4:6], uint16(m.Index))
	binary.NativeEndian.PutUint32(b[8:12], uint32(m.Flags))
	binary.NativeEndian.PutUint32(b[12:16], attrs)
	binary.NativeEndian.PutUint32(b[16:20], uint32(m.ID))
	binary.NativeEndian.PutUint32(b[20:24], uint32(m.Seq))
	return b, nil
}
