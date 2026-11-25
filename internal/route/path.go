package route

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/xvzc/spoofdpi/internal/netutil"
)

// ErrNoIPv6 is returned, wrapped, by Lookup when the kernel has no
// route to an IPv6 destination.
var ErrNoIPv6 = errors.New("no IPv6 route")

// Probe destinations are documentation addresses (RFC 5737, RFC 3849):
// they are routed like any internet address but never answer. Lookup
// sends no packet to them.
var (
	probeDstV4 = netip.MustParseAddr("192.0.2.1")
	probeDstV6 = netip.MustParseAddr("2001:db8::1")
)

// probeDst returns the probe destination of fam, which stands for "the
// internet" in route lookups.
func probeDst(fam netutil.Family) netip.Addr {
	if fam == netutil.FamilyV6 {
		return probeDstV6
	}
	return probeDstV4
}

// Path is the kernel's route to one destination.
type Path struct {
	Family netutil.Family
	Dst    netip.Addr
	// Iface is the output interface.
	Iface net.Interface
	// Gateway is the next hop, or the zero Addr for an interface route,
	// which reaches Dst through Iface without a gateway.
	Gateway netip.Addr
	// Zone is Iface's name when Gateway is an IPv6 link-local address,
	// and empty otherwise.
	Zone string
	// Src is the route's interface address on darwin and FreeBSD, and the
	// kernel's preferred source address on Linux. It may be the zero Addr.
	Src netip.Addr
	// Table is the Linux routing table that holds the route, and 0 on
	// other OSes.
	Table int
}

// Route returns the path as a Route. Its Gateway is nil for an interface
// route, and its LocalIP is nil when Src is unknown.
func (p *Path) Route() *Route {
	r := &Route{Family: p.Family, Iface: p.Iface, Zone: p.Zone}
	if p.Gateway.IsValid() {
		r.Gateway = net.IP(p.Gateway.AsSlice())
	}
	if p.Src.IsValid() {
		r.LocalIP = net.IP(p.Src.AsSlice())
	}
	return r
}

// kernelRoute is the kernel's answer to a route lookup, before the output
// interface is resolved.
type kernelRoute struct {
	ifIndex int
	// gateway is the zero Addr when the route has no gateway.
	gateway netip.Addr
	// src is the zero Addr when the kernel did not report it.
	src   netip.Addr
	table int
}

// osRouteTo asks the kernel for its route to dst, which is valid, unzoned
// and not an IPv4-mapped IPv6 address. It returns ErrNoIPv4 or
// ErrNoIPv6, wrapped, when there is none. It backs Lookup. Tests replace
// it.
var osRouteTo = routeTo

// interfaceByIndex resolves the output interface of a route. Tests
// replace it.
var interfaceByIndex = net.InterfaceByIndex

// Lookup returns the kernel's route to dst, as the kernel would choose it
// for a socket connected to dst. It sends no packet and needs no
// privileges. An IPv4-mapped IPv6 address is looked up as IPv4. IPv6
// link-local and multicast destinations are refused: their route depends
// on a zone or an interface that Lookup cannot express.
//
// Loopback lookups differ by OS: darwin and FreeBSD return the loopback
// interface, while Linux reports a local route, which Lookup returns as
// an error.
func Lookup(dst netip.Addr) (*Path, error) {
	if !dst.IsValid() {
		return nil, errors.New("route lookup: invalid destination")
	}
	if dst.Zone() != "" {
		return nil, fmt.Errorf("route lookup %s: zoned destinations are not supported", dst)
	}
	dst = dst.Unmap()
	if dst.IsMulticast() {
		return nil, fmt.Errorf(
			"route lookup %s: multicast destinations are not supported",
			dst,
		)
	}
	if dst.Is6() && dst.IsLinkLocalUnicast() {
		return nil, fmt.Errorf(
			"route lookup %s: link-local destinations need a zone, which is not supported",
			dst,
		)
	}

	kr, err := osRouteTo(dst)
	if err != nil {
		return nil, err
	}
	iface, err := interfaceByIndex(kr.ifIndex)
	if err != nil {
		return nil, fmt.Errorf(
			"route lookup %s: output interface %d: %w", dst, kr.ifIndex, err,
		)
	}
	return newPath(dst, *iface, kr)
}

// newPath builds the Path to dst through iface from the kernel's answer.
func newPath(dst netip.Addr, iface net.Interface, kr kernelRoute) (*Path, error) {
	p := &Path{
		Family: familyOf(dst),
		Dst:    dst,
		Iface:  iface,
		Table:  kr.table,
	}
	if gw := kr.gateway.Unmap(); gw.IsValid() && !gw.IsUnspecified() {
		if gw.Is4() != dst.Is4() {
			return nil, fmt.Errorf(
				"route lookup %s: gateway %s is of the other address family",
				dst,
				gw,
			)
		}
		p.Gateway = gw.WithZone("")
		if p.Gateway.Is6() && p.Gateway.IsLinkLocalUnicast() {
			p.Zone = iface.Name
		}
	}
	if src := kr.src.Unmap(); src.IsValid() && src.Is4() == dst.Is4() {
		p.Src = src.WithZone("")
	}
	return p, nil
}

// familyOf returns the family of addr, which is valid and unmapped.
func familyOf(addr netip.Addr) netutil.Family {
	if addr.Is4() {
		return netutil.FamilyV4
	}
	return netutil.FamilyV6
}

// errNoRoute returns the error for a destination the kernel has no route
// to.
func errNoRoute(dst netip.Addr) error {
	if familyOf(dst) == netutil.FamilyV6 {
		return fmt.Errorf("route lookup %s: %w", dst, ErrNoIPv6)
	}
	return fmt.Errorf("route lookup %s: %w", dst, ErrNoIPv4)
}
