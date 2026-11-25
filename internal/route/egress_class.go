package route

import "fmt"

// LinkKind is what kind of link an interface is, as far as deciding
// whether traffic through it leaves the host directly.
type LinkKind uint8

const (
	LinkUnknown LinkKind = iota
	// LinkPhysical is Ethernet, Wi-Fi, a cellular modem, or a bond,
	// bridge, VLAN or veth on top of them.
	LinkPhysical
	// LinkPPP is PPPoE, cellular PPP, or an L2TP/PPTP VPN: it may be the
	// uplink or a VPN.
	LinkPPP
	// LinkIPTunnel is 6in4, sit, gif, stf, ipip or gre: it may be the
	// uplink or a VPN.
	LinkIPTunnel
	// LinkVPN is WireGuard, a Linux tun, a darwin utun or ipsec, xfrm, vti
	// or ovpn.
	LinkVPN
	LinkLoopback
)

func (k LinkKind) String() string {
	switch k {
	case LinkPhysical:
		return "physical"
	case LinkPPP:
		return "ppp"
	case LinkIPTunnel:
		return "ip-tunnel"
	case LinkVPN:
		return "vpn"
	case LinkLoopback:
		return "loopback"
	default:
		return "unknown"
	}
}

// LinkInfo describes the link of one interface.
type LinkInfo struct {
	Index int
	Name  string
	Kind  LinkKind
	// Detail is the OS evidence for Kind, for logs, such as
	// "kind=wireguard", "ARPHRD_PPP" or "IFT_OTHER p2p".
	Detail string
}

// EgressClass is how traffic of one family leaves the host.
type EgressClass uint8

const (
	// EgressDirect is a physical link.
	EgressDirect EgressClass = iota
	// EgressUplink is a point-to-point link that is the uplink, such as
	// PPP, cellular or 6in4.
	EgressUplink
	// EgressVPN is a full-tunnel VPN.
	EgressVPN
	// EgressUnknown is a link that cannot be told apart.
	EgressUnknown
)

func (c EgressClass) String() string {
	switch c {
	case EgressDirect:
		return "direct"
	case EgressUplink:
		return "uplink"
	case EgressVPN:
		return "vpn"
	default:
		return "unknown"
	}
}

// Egress is the classified egress of one family.
type Egress struct {
	// Route has the egress interface, the gateway (nil for an interface
	// route), the zone, and the source address as LocalIP.
	Route  Route
	Link   LinkInfo
	Class  EgressClass
	Reason string
}

// ClassifyEgress classifies the egress link of one family. others are the
// links of the default routes of the same family, which may include link
// itself. Another physical default route next to the egress means a VPN
// has taken over the traffic: it turns an ambiguous or unknown link into a
// VPN. The reason explains the class for logs.
//
// A loopback link, which never leaves the host, is EgressUnknown with the
// reason "loopback link"; DiscoverEgress is to report it as no route.
func ClassifyEgress(link LinkInfo, others []LinkInfo) (EgressClass, string) {
	desc := describeLink(link)
	switch link.Kind {
	case LinkLoopback:
		return EgressUnknown, "loopback link " + desc
	case LinkPhysical:
		return EgressDirect, "physical link " + desc
	case LinkVPN:
		return EgressVPN, "VPN link " + desc
	}

	phys, ok := otherPhysical(link, others)
	switch {
	case ok:
		return EgressVPN, fmt.Sprintf(
			"%s link %s carries the traffic while physical link %s also has a default route",
			link.Kind,
			desc,
			describeLink(phys),
		)
	case link.Kind == LinkPPP || link.Kind == LinkIPTunnel:
		return EgressUplink, fmt.Sprintf(
			"%s link %s is the only default route",
			link.Kind,
			desc,
		)
	default:
		return EgressUnknown, "cannot tell whether " + desc + " is a VPN"
	}
}

// otherPhysical returns the first physical link among others that is not
// link itself.
func otherPhysical(link LinkInfo, others []LinkInfo) (LinkInfo, bool) {
	for _, o := range others {
		if o.Kind == LinkPhysical && o.Index != link.Index {
			return o, true
		}
	}
	return LinkInfo{}, false
}

// describeLink returns the name of link with its detail, such as
// "wg0 (kind=wireguard)".
func describeLink(link LinkInfo) string {
	name := link.Name
	if name == "" {
		name = fmt.Sprintf("#%d", link.Index)
	}
	if link.Detail == "" {
		return name
	}
	return name + " (" + link.Detail + ")"
}
