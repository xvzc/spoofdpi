package route

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/xvzc/spoofdpi/internal/netutil"
)

// Linux route constants (<linux/rtnetlink.h>); see netlink.go for why
// they are kept here.
const (
	rtaPriority    = 6
	rtaNhID        = 30
	rtScopeNowhere = 255
)

// Route scopes (rtm_scope, <linux/rtnetlink.h>) of a RouteEntry. The
// kernel keeps and compares the scope of IPv4 routes only: it stores and
// dumps every IPv6 route as RouteScopeUniverse.
const (
	// RouteScopeUniverse is the scope of a route through a gateway.
	RouteScopeUniverse uint8 = 0
	// RouteScopeLink is the scope of an IPv4 route to the hosts on a link,
	// such as `ip route add default dev tun0`.
	RouteScopeLink uint8 = 253
)

// RouteTypeUnicast is the rtm_type of a route to a gateway or a link.
const RouteTypeUnicast uint8 = rtnUnicast

// RouteEntry is a route in a Linux routing table, as RTM_NEWROUTE carries
// it.
type RouteEntry struct {
	// Table is the routing table (RTA_TABLE), which may be above 255.
	Table uint32
	// Dst is the destination prefix, with its host bits zero; 0.0.0.0/0
	// or ::/0 is the default route. Its address family is the route's.
	Dst netip.Prefix
	// Oif is the interface index of the output link (RTA_OIF), or 0 for
	// none.
	Oif int
	// Gateway is the next hop (RTA_GATEWAY), of Dst's family, or the zero
	// Addr for none.
	Gateway netip.Addr
	// Metric is the route's priority (RTA_PRIORITY), or 0 for none. The
	// kernel gives an IPv6 route without one the metric 1024.
	Metric uint32
	// Protocol is rtm_protocol, the tag of the route's origin.
	Protocol uint8
	// Scope is rtm_scope, such as RouteScopeLink; see RouteScopeUniverse
	// for IPv6.
	Scope uint8
	// Type is rtm_type. AddRoute sends RouteTypeUnicast when it is zero;
	// DeleteRoute sends it as it is.
	Type uint8
	// TOS is rtm_tos, the type of service an IPv4 route is for, or 0 for
	// any. DeleteRoute refuses a nonzero one.
	TOS uint8
	// OtherAttrs are the types of the attributes of a dumped route that
	// the fields above do not hold, such as RTA_PREFSRC, RTA_MULTIPATH,
	// RTA_VIA or RTA_METRICS, in dump order. IPv6 routes always carry
	// RTA_CACHEINFO and RTA_PREF. AddRoute and DeleteRoute do not send
	// them.
	OtherAttrs []uint16
}

func (r RouteEntry) String() string {
	dst := r.Dst.String()
	if r.Dst.Bits() == 0 {
		dst = "default"
	}
	s := dst
	if r.Gateway.IsValid() {
		s += " via " + r.Gateway.String()
	}
	if r.Oif != 0 {
		s += fmt.Sprintf(" dev %d", r.Oif)
	}
	if r.Metric != 0 {
		s += fmt.Sprintf(" metric %d", r.Metric)
	}
	if len(r.OtherAttrs) > 0 {
		s += fmt.Sprintf(" attrs %v", r.OtherAttrs)
	}
	if r.TOS != 0 {
		s += fmt.Sprintf(" tos %#x", r.TOS)
	}
	return fmt.Sprintf(
		"%s table %d proto %d scope %d type %d",
		s, r.Table, r.Protocol, r.Scope, r.Type,
	)
}

// checkRoute returns an error when r cannot be sent: a destination that
// is missing or has host bits set, or a gateway of another family.
func checkRoute(r RouteEntry) error {
	if !r.Dst.IsValid() {
		return errors.New("no destination")
	}
	if r.Dst != r.Dst.Masked() {
		return fmt.Errorf("destination %s has host bits set", r.Dst)
	}
	if r.Gateway.IsValid() && r.Gateway.Is4() != r.Dst.Addr().Is4() {
		return fmt.Errorf("gateway %s is of another family than %s", r.Gateway, r.Dst)
	}
	return nil
}

// checkRouteDelete returns an error when r is not a tagged route of a
// chosen table: the kernel takes a zero table as the main table and a zero
// protocol as any, so such a delete could remove a route that someone else
// added. It also refuses a nonzero TOS: spoofdpi adds no such route, and
// RouteDeleteAmbiguous does not model the TOS that the IPv4 kernel looks
// routes up by.
func checkRouteDelete(r RouteEntry) error {
	if err := checkRoute(r); err != nil {
		return err
	}
	if r.Table == 0 {
		return errors.New("no table")
	}
	if r.Protocol == 0 {
		return errors.New("no protocol tag")
	}
	if r.TOS != 0 {
		return fmt.Errorf("TOS %#x", r.TOS)
	}
	return nil
}

// encodeRouteModify returns an RTM_NEWROUTE (add) or RTM_DELROUTE request
// for r, which checkRoute accepts. The table goes in RTA_TABLE, so that
// tables above 255 work. See routeDeleteMatches for the routes a delete
// removes.
func encodeRouteModify(seq uint32, r RouteEntry, add bool) []byte {
	var attrs []byte
	attrs = appendAttr(attrs, rtaTable, binary.NativeEndian.AppendUint32(nil, r.Table))
	if r.Dst.Bits() > 0 {
		attrs = appendAttr(attrs, rtaDst, r.Dst.Addr().AsSlice())
	}
	if r.Oif != 0 {
		attrs = appendAttr(
			attrs,
			rtaOif,
			binary.NativeEndian.AppendUint32(nil, uint32(int32(r.Oif))),
		)
	}
	if r.Gateway.IsValid() {
		attrs = appendAttr(attrs, rtaGateway, r.Gateway.AsSlice())
	}
	if r.Metric != 0 {
		attrs = appendAttr(
			attrs,
			rtaPriority,
			binary.NativeEndian.AppendUint32(nil, r.Metric),
		)
	}

	typ := uint16(rtmDelRoute)
	routeType := r.Type
	if add {
		typ = rtmNewRoute
		if routeType == 0 {
			routeType = rtnUnicast
		}
	}
	b := appendModifyHeader(nil, rtmsgLen+len(attrs), typ, seq, add)
	b = append(b,
		linuxFamily(familyOf(r.Dst.Addr())), // rtm_family
		uint8(r.Dst.Bits()),                 // rtm_dst_len
		0,                                   // rtm_src_len
		r.TOS,
		0, // rtm_table: RTA_TABLE instead
		r.Protocol,
		r.Scope,
		routeType,
	)
	b = binary.NativeEndian.AppendUint32(b, 0) // rtm_flags
	return append(b, attrs...)
}

// routeEntriesFromNetlink reads the routes of fam from reply, a route dump
// (encodeRouteDump).
func routeEntriesFromNetlink(
	reply []netlinkMessage,
	fam netutil.Family,
) ([]RouteEntry, error) {
	var routes []RouteEntry
	for _, m := range reply {
		if m.typ != rtmNewRoute {
			continue
		}
		r, err := parseNetlinkRoute(m.data)
		if err != nil {
			return nil, err
		}
		if r.family != linuxFamily(fam) {
			continue
		}
		dst, err := routeDst(r, fam)
		if err != nil {
			return nil, err
		}
		entry := RouteEntry{
			Table:    uint32(r.table),
			Dst:      dst,
			Oif:      r.oif,
			Gateway:  r.gateway,
			Protocol: r.protocol,
			Scope:    r.scope,
			Type:     r.typ,
			TOS:      m.data[3],
		}
		// parseNetlinkRoute already rejected malformed attributes.
		_ = walkAttrs(m.data[rtmsgLen:], func(typ uint16, val []byte) {
			switch typ {
			case rtaTable, rtaDst, rtaOif, rtaGateway:
			case rtaPriority:
				if len(val) >= 4 {
					entry.Metric = binary.NativeEndian.Uint32(val)
				}
			default:
				entry.OtherAttrs = append(entry.OtherAttrs, typ)
			}
		})
		routes = append(routes, entry)
	}
	return routes, nil
}

// routeDst returns the destination prefix of r, a route of fam. A default
// route carries no RTA_DST.
func routeDst(r netlinkRoute, fam netutil.Family) (netip.Prefix, error) {
	if r.dstLen == 0 {
		if fam == netutil.FamilyV6 {
			return netip.PrefixFrom(netip.IPv6Unspecified(), 0), nil
		}
		return netip.PrefixFrom(netip.IPv4Unspecified(), 0), nil
	}
	if !r.dst.IsValid() || familyOf(r.dst) != fam || int(r.dstLen) > r.dst.BitLen() {
		return netip.Prefix{}, errors.New("netlink: route without a valid destination")
	}
	return netip.PrefixFrom(r.dst, int(r.dstLen)), nil
}

// RouteDeleteAmbiguous reports whether DeleteRoute(target) could delete a
// route of dump, a fresh Routes dump of target's family, other than
// target: when the kernel's delete filter matches more than one route of
// dump, or one route that is not target. The kernel deletes the first
// match. It errs on the side of ambiguity where the dump does not show
// what the kernel compares, such as the next hops of a multipath route.
// Pass a route of dump as target: a route that only resembles one, such
// as an IPv6 route without the metric and attributes that the kernel
// dumps, counts as another route.
func RouteDeleteAmbiguous(target RouteEntry, dump []RouteEntry) bool {
	var matches []RouteEntry
	for _, r := range dump {
		if routeDeleteMatches(target, r) {
			matches = append(matches, r)
		}
	}
	return len(matches) > 1 || len(matches) == 1 && !routesEqual(matches[0], target)
}

// routeDeleteMatches reports whether the kernel's delete of filter, as
// encodeRouteModify sends it, could remove r. Both kernels look up the
// table and the exact prefix, and then ignore a zero protocol, metric,
// output link and gateway. IPv4 also compares a nonzero type and the
// scope; IPv6 ignores both. The TOS that the IPv4 kernel looks routes up
// by is not compared, so routes that differ only in it count as matches. A
// route whose next hops the dump hides
// (RTA_MULTIPATH or a nexthop object, RTA_NH_ID) counts as a match for any
// output link and gateway.
func routeDeleteMatches(filter, r RouteEntry) bool {
	if r.Table != filter.Table || r.Dst != filter.Dst {
		return false
	}
	if filter.Dst.Addr().Is4() {
		if filter.Type != 0 && r.Type != filter.Type {
			return false
		}
		if filter.Scope != rtScopeNowhere && r.Scope != filter.Scope {
			return false
		}
	}
	if filter.Protocol != 0 && r.Protocol != filter.Protocol {
		return false
	}
	if filter.Metric != 0 && r.Metric != filter.Metric {
		return false
	}
	hiddenNexthops := slices.ContainsFunc(r.OtherAttrs, func(typ uint16) bool {
		return typ == rtaMultipath || typ == rtaNhID
	})
	if hiddenNexthops {
		return true
	}
	if filter.Oif != 0 && r.Oif != filter.Oif {
		return false
	}
	return !filter.Gateway.IsValid() || r.Gateway == filter.Gateway
}

// routesEqual reports whether a and b are the same in every field.
func routesEqual(a, b RouteEntry) bool {
	return a.Table == b.Table && a.Dst == b.Dst && a.Oif == b.Oif &&
		a.Gateway == b.Gateway && a.Metric == b.Metric &&
		a.Protocol == b.Protocol && a.Scope == b.Scope && a.Type == b.Type &&
		a.TOS == b.TOS &&
		slices.Equal(a.OtherAttrs, b.OtherAttrs)
}
