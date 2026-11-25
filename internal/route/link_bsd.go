//go:build darwin || freebsd

package route

import (
	"fmt"
	"slices"

	"github.com/xvzc/spoofdpi/internal/netutil"
	xroute "golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// linkInfo returns the link of the interface with index, read from the
// interface list of the routing sysctl.
func linkInfo(index int) (LinkInfo, error) {
	rib, err := xroute.FetchRIB(unix.AF_UNSPEC, xroute.RIBTypeInterface, index)
	if err != nil {
		return LinkInfo{}, fmt.Errorf("link %d: %w", index, err)
	}
	msgs, err := xroute.ParseRIB(xroute.RIBTypeInterface, rib)
	if err != nil {
		return LinkInfo{}, fmt.Errorf("link %d: parse interface list: %w", index, err)
	}
	for _, msg := range msgs {
		m, ok := msg.(*xroute.InterfaceMessage)
		if !ok || m.Index != index {
			continue
		}
		ifType := -1
		for _, sys := range m.Sys() {
			if mx, ok := sys.(*xroute.InterfaceMetrics); ok {
				ifType = mx.Type
			}
		}
		return bsdLinkInfo(index, m.Name, m.Flags, ifType), nil
	}
	return LinkInfo{}, fmt.Errorf("link %d: no such interface", index)
}

// bsdLinkInfo returns the link of an interface from its interface flags
// and its type (if_data.ifi_type), or -1 when the type is unknown.
func bsdLinkInfo(index int, name string, flags, ifType int) LinkInfo {
	p2p := flags&unix.IFF_POINTOPOINT != 0
	kind := bsdLinkKind(ifType, p2p)
	if flags&unix.IFF_LOOPBACK != 0 {
		kind = LinkLoopback
	}
	detail := bsdLinkTypeName(ifType)
	if p2p {
		detail += " p2p"
	}
	return LinkInfo{Index: index, Name: name, Kind: kind, Detail: detail}
}

// bsdLinkTypeName returns the name of the interface type ifType for logs.
func bsdLinkTypeName(ifType int) string {
	if name, ok := bsdLinkTypeNames[ifType]; ok {
		return name
	}
	if ifType < 0 {
		return "IFT_?"
	}
	return fmt.Sprintf("IFT_%#x", ifType)
}

// defaultLinks returns the links of the default routes of fam, in table
// order and without duplicates. Scoped defaults (RTF_IFSCOPE) are
// included: a darwin VPN demotes the physical default to one. A default
// whose link cannot be read is left out.
func defaultLinks(fam netutil.Family) ([]LinkInfo, error) {
	af := unix.AF_INET
	if fam == netutil.FamilyV6 {
		af = unix.AF_INET6
	}
	rib, err := xroute.FetchRIB(af, xroute.RIBTypeRoute, 0)
	if err != nil {
		return nil, fmt.Errorf("%s default routes: %w", fam, err)
	}
	msgs, err := xroute.ParseRIB(xroute.RIBTypeRoute, rib)
	if err != nil {
		return nil, fmt.Errorf("%s default routes: parse: %w", fam, err)
	}

	return resolveLinks(defaultRouteIndexes(msgs, fam), linkInfo), nil
}

// defaultRouteIndexes returns the interface indexes of the default routes
// of fam among msgs, a routing table dump, in dump order and without
// duplicates. A default route has an unspecified destination of fam, no
// netmask or a zero one, is up, has an interface, and is not a host,
// reject or blackhole route.
func defaultRouteIndexes(msgs []xroute.Message, fam netutil.Family) []int {
	var indexes []int
	for _, msg := range msgs {
		m, ok := msg.(*xroute.RouteMessage)
		if !ok || !isDefaultRouteMessage(m, fam) || slices.Contains(indexes, m.Index) {
			continue
		}
		indexes = append(indexes, m.Index)
	}
	return indexes
}

func isDefaultRouteMessage(m *xroute.RouteMessage, fam netutil.Family) bool {
	dst := addrIP(ribAddr(m.Addrs, unix.RTAX_DST))
	if !dst.IsValid() || familyOf(dst) != fam || !dst.IsUnspecified() {
		return false
	}
	if mask := ribAddr(m.Addrs, unix.RTAX_NETMASK); mask != nil {
		if ip := addrIP(mask); !ip.IsValid() || !ip.IsUnspecified() {
			return false
		}
	}
	return m.Flags&unix.RTF_UP != 0 &&
		m.Flags&(unix.RTF_HOST|unix.RTF_REJECT|unix.RTF_BLACKHOLE) == 0 &&
		m.Index > 0
}
