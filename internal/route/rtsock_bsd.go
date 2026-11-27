//go:build darwin || freebsd

package route

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"

	"github.com/xvzc/spoofdpi/internal/netutil"
	xroute "golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// TableRoute is a route of a kernel routing table as the routing socket
// writes it with AddRoute and DeleteRoute and as DumpRoutes reads it.
type TableRoute struct {
	// Dst is the destination; 0.0.0.0/0 or ::/0 for a default route.
	Dst netip.Prefix
	// Gateway is the IP gateway, or the zero Addr for an interface route.
	// It has no zone.
	Gateway netip.Addr
	// GatewayLink is the interface index of a link-layer gateway, as
	// `route add -interface` sets it, or 0.
	GatewayLink int
	// Index is the interface index of rtm_index. darwin reads it on a
	// write as the scope of an RTF_IFSCOPE route; in a dump it is the
	// route's interface.
	Index int
	// IfName is the name of the route's interface in a dump: the one the
	// kernel reports, or else the name of the interface Index, which darwin
	// dumps report alone. It is empty when that interface is gone or the
	// interfaces cannot be read, so callers match routes on Index and
	// GatewayLink, not on IfName. Writes ignore it.
	IfName string
	// Flags are the RTF_* flags. On a write, those a caller may set are
	// added to those AddRoute and DeleteRoute set themselves:
	// RTF_PROTO1, RTF_PROTO2, RTF_PROTO3, RTF_BLACKHOLE, RTF_REJECT and,
	// on darwin, RTF_IFSCOPE. The others, such as the kernel's own bits in
	// a dumped route, are dropped. In a dump they are the route's flags as
	// the kernel reports them.
	Flags int
}

// String describes r for logs and errors, such as
// "192.0.2.0/24 gateway 192.0.2.1 index 4 flags 0x40803".
func (r TableRoute) String() string {
	s := r.Dst.String()
	if r.Gateway.IsValid() {
		s += " gateway " + r.Gateway.String()
	}
	if r.GatewayLink > 0 {
		s += fmt.Sprintf(" gateway link#%d", r.GatewayLink)
	}
	if r.Index > 0 {
		s += fmt.Sprintf(" index %d", r.Index)
	}
	if r.IfName != "" {
		s += " (" + r.IfName + ")"
	}
	return s + fmt.Sprintf(" flags %#x", r.Flags)
}

// AddRoute adds r to the routing table of fib with RTM_ADD, as
// `route add` does. It sets RTF_UP and RTF_STATIC, RTF_GATEWAY for an IP
// gateway, and RTF_HOST for a destination of full length, which is sent
// without netmask. r needs a gateway: an IP or a link. darwin has no FIBs
// and accepts fib 0 only. A failure of the kernel wraps its errno, such as
// unix.EEXIST for a route that exists.
func AddRoute(fib int, r TableRoute) error {
	if !r.Gateway.IsValid() && r.GatewayLink <= 0 {
		return fmt.Errorf("add route %s: no gateway", r)
	}
	if err := writeRouteMessage(unix.RTM_ADD, fib, r); err != nil {
		return fmt.Errorf("add route %s: %w", r, err)
	}
	return nil
}

// DeleteRoute deletes the route to r.Dst from the routing table of fib
// with RTM_DELETE, as `route delete` does. Which route that is differs:
//   - darwin finds it by destination, netmask and scope: an RTF_IFSCOPE
//     route only with RTF_IFSCOPE and its Index in r, any other only
//     without RTF_IFSCOPE. It does not check the gateway, so DeleteRoute
//     leaves it out of the message, and the tag marks nothing either.
//   - FreeBSD finds it by destination and netmask. A gateway, IP or link,
//     narrows the delete to the route through it; without one, the route
//     goes whatever its gateway.
//
// Neither kernel checks the flags, such as the tag RTF_PROTO2. darwin drops
// RTF_PROTO3 from RTM_ADD, so it cannot be a tag there. A caller
// that must delete only its own route matches r on an entry of a dump
// read just before, by its tag, RTF_STATIC, no RTF_WASCLONED and its exact
// shape. A failure of the kernel wraps its errno, such as unix.ESRCH for
// a route that does not exist.
func DeleteRoute(fib int, r TableRoute) error {
	if err := writeRouteMessage(unix.RTM_DELETE, fib, r); err != nil {
		return fmt.Errorf("delete route %s: %w", r, err)
	}
	return nil
}

// DumpRoutes returns the routes of fam in the routing table of fib, read
// from the routing sysctl (NET_RT_DUMP), in table order. darwin has no
// FIBs and accepts fib 0 only. A route whose destination is not an
// address of fam or whose netmask is not a prefix of it is left out.
func DumpRoutes(fam netutil.Family, fib int) ([]TableRoute, error) {
	rib, err := fetchRouteDump(familyAF(fam), fib)
	if err != nil {
		return nil, fmt.Errorf("dump %s routes of fib %d: %w", fam, fib, err)
	}
	msgs, err := xroute.ParseRIB(xroute.RIBTypeRoute, rib)
	if err != nil {
		return nil, fmt.Errorf("dump %s routes of fib %d: parse: %w", fam, fib, err)
	}
	// The names only help logs: without them, the routes have no IfName.
	ifaces, _ := net.Interfaces()
	names := make(map[int]string, len(ifaces))
	for _, iface := range ifaces {
		names[iface.Index] = iface.Name
	}
	return tableRoutes(msgs, fam, names), nil
}

// writeRouteMessage sends one routing message of type typ for r over a
// routing socket of fib. The kernel reports a failed request as the error
// of the write, so the reply is not read.
func writeRouteMessage(typ, fib int, r TableRoute) error {
	if err := checkFIB(fib); err != nil {
		return err
	}
	m, err := routeMessage(typ, r, linkGateway)
	if err != nil {
		return err
	}
	b, err := marshalRouteMessage(m)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	fd, err := routeSocket(familyAF(familyOf(r.Dst.Addr())))
	if err != nil {
		return os.NewSyscallError("socket", err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := setRouteSocketFIB(fd, fib); err != nil {
		return err
	}
	if _, err := unix.Write(fd, b); err != nil {
		return os.NewSyscallError("write", err)
	}
	return nil
}

// routeMessage returns the routing message of type typ for r, with the
// flags and addresses of `route add` and `route delete`. link returns the
// sockaddr_dl of a link gateway from its interface index. A delete on
// darwin, which does not check the gateway, carries none.
func routeMessage(
	typ int,
	r TableRoute,
	link func(index int) (*xroute.LinkAddr, error),
) (*xroute.RouteMessage, error) {
	if !r.Dst.IsValid() {
		return nil, errors.New("invalid destination")
	}
	dst := r.Dst.Masked()
	if r.Gateway.IsValid() {
		if r.Gateway.Is4() != dst.Addr().Is4() {
			return nil, errors.New("gateway of another address family")
		}
		if r.GatewayLink > 0 {
			return nil, errors.New("both an IP and a link gateway")
		}
	}
	withGateway := typ != unix.RTM_DELETE || deleteMatchesGateway

	flags := unix.RTF_UP | unix.RTF_STATIC | r.Flags&callerRouteFlags
	addrs := make([]xroute.Addr, unix.RTAX_NETMASK+1)
	addrs[unix.RTAX_DST] = routeAddr(dst.Addr())
	switch {
	case !withGateway:
	case r.Gateway.IsValid():
		// The kernel expects the scope of an IPv6 link-local gateway in a
		// form that differs between darwin and FreeBSD; no caller needs
		// one. An IPv4 link-local gateway has no scope and goes as is.
		if r.Gateway.Is6() &&
			(r.Gateway.Zone() != "" || r.Gateway.IsLinkLocalUnicast()) {
			return nil, errors.New("link-local gateway is not supported")
		}
		flags |= unix.RTF_GATEWAY
		addrs[unix.RTAX_GATEWAY] = routeAddr(r.Gateway)
	case r.GatewayLink > 0:
		gw, err := link(r.GatewayLink)
		if err != nil {
			return nil, fmt.Errorf("gateway link#%d: %w", r.GatewayLink, err)
		}
		addrs[unix.RTAX_GATEWAY] = gw
	}
	if dst.IsSingleIP() {
		flags |= unix.RTF_HOST
	} else {
		mask := net.CIDRMask(dst.Bits(), dst.Addr().BitLen())
		addr, _ := netip.AddrFromSlice(mask)
		addrs[unix.RTAX_NETMASK] = routeAddr(addr)
	}

	return &xroute.RouteMessage{
		Version: unix.RTM_VERSION,
		Type:    typ,
		Flags:   flags,
		Index:   r.Index,
		ID:      uintptr(os.Getpid()),
		Seq:     int(rtmSeq.Add(1)),
		Addrs:   addrs,
	}, nil
}

// tableRoutes returns the routes of fam among msgs, a routing table dump,
// in dump order. names maps interface indexes to names. See DumpRoutes for
// the routes left out.
func tableRoutes(
	msgs []xroute.Message,
	fam netutil.Family,
	names map[int]string,
) []TableRoute {
	var routes []TableRoute
	for _, msg := range msgs {
		m, ok := msg.(*xroute.RouteMessage)
		if !ok {
			continue
		}
		r, ok := tableRouteFromMessage(m, fam, names)
		if ok {
			routes = append(routes, r)
		}
	}
	return routes
}

// tableRouteFromMessage reads the route of fam from m, a routing table
// dump entry, with the interface name from names when m lacks it. ok is
// false when m is not one. A route without netmask is a host route: the
// kernel keeps those without mask.
func tableRouteFromMessage(
	m *xroute.RouteMessage,
	fam netutil.Family,
	names map[int]string,
) (TableRoute, bool) {
	dst := addrIP(ribAddr(m.Addrs, unix.RTAX_DST))
	if !dst.IsValid() || familyOf(dst) != fam {
		return TableRoute{}, false
	}
	bits := dst.BitLen()
	if mask := ribAddr(m.Addrs, unix.RTAX_NETMASK); mask != nil {
		ip := addrIP(mask)
		if !ip.IsValid() {
			return TableRoute{}, false
		}
		ones, maskBits := net.IPMask(ip.AsSlice()).Size()
		if maskBits != dst.BitLen() {
			return TableRoute{}, false
		}
		bits = ones
	}

	r := TableRoute{
		Dst:   netip.PrefixFrom(dst, bits),
		Index: m.Index,
		Flags: m.Flags,
	}
	switch gw := ribAddr(m.Addrs, unix.RTAX_GATEWAY).(type) {
	case *xroute.LinkAddr:
		r.GatewayLink = gw.Index
	case *xroute.Inet4Addr, *xroute.Inet6Addr:
		r.Gateway = addrIP(gw)
	}
	r.IfName = names[m.Index]
	ifp, ok := ribAddr(m.Addrs, unix.RTAX_IFP).(*xroute.LinkAddr)
	if ok && ifp.Name != "" {
		r.IfName = ifp.Name
	}
	return r, true
}

// familyAF returns the address family constant of fam.
func familyAF(fam netutil.Family) int {
	if fam == netutil.FamilyV6 {
		return unix.AF_INET6
	}
	return unix.AF_INET
}
