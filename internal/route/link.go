package route

import "fmt"

// LinkKind is what kind of link an interface is.
type LinkKind uint8

const (
	LinkUnknown LinkKind = iota
	// LinkPhysical is Ethernet, Wi-Fi, a cellular modem, or a bond,
	// bridge, VLAN or veth on top of them.
	LinkPhysical
	// LinkPPP is PPPoE, cellular PPP, or an L2TP/PPTP VPN.
	LinkPPP
	// LinkIPTunnel is 6in4, sit, gif, stf, ipip or gre.
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
