package route

import "syscall"

// FreeBSD interface types of <net/if_types.h> that neither syscall nor
// x/sys/unix defines. syscall's tables predate them: its IFT_CARP, from an
// older if_types.h, has the value that IFT_WIREGUARD reuses.
const (
	ifTypeWireGuard = 0xf8 // IFT_WIREGUARD
	ifTypeMBIM      = 0xf9 // IFT_MBIM, a cellular modem
)

// bsdLinkKind returns the kind of a FreeBSD interface of type ifType.
//   - tun is IFT_PPP and serves both ppp(8) and OpenVPN, so it counts as
//     PPP: whether it is the uplink is left to the other default routes.
//   - tap and vmnet are IFT_ETHER, so they count as physical.
//   - ovpn is IFT_TUNNEL like gre, so it counts as an IP tunnel and is
//     likewise decided by the other default routes.
func bsdLinkKind(ifType int, _ bool) LinkKind {
	switch ifType {
	case syscall.IFT_ETHER, syscall.IFT_BRIDGE, syscall.IFT_L2VLAN,
		syscall.IFT_IEEE8023ADLAG, ifTypeMBIM:
		return LinkPhysical
	case ifTypeWireGuard:
		return LinkVPN
	case syscall.IFT_PPP:
		return LinkPPP
	case syscall.IFT_GIF, syscall.IFT_TUNNEL, syscall.IFT_STF:
		return LinkIPTunnel
	case syscall.IFT_LOOP:
		return LinkLoopback
	}
	return LinkUnknown
}

// bsdLinkTypeNames names the interface types of bsdLinkKind for logs.
var bsdLinkTypeNames = map[int]string{
	syscall.IFT_ETHER:         "IFT_ETHER",
	syscall.IFT_BRIDGE:        "IFT_BRIDGE",
	syscall.IFT_L2VLAN:        "IFT_L2VLAN",
	syscall.IFT_IEEE8023ADLAG: "IFT_IEEE8023ADLAG",
	ifTypeMBIM:                "IFT_MBIM",
	ifTypeWireGuard:           "IFT_WIREGUARD",
	syscall.IFT_PPP:           "IFT_PPP",
	syscall.IFT_GIF:           "IFT_GIF",
	syscall.IFT_TUNNEL:        "IFT_TUNNEL",
	syscall.IFT_STF:           "IFT_STF",
	syscall.IFT_LOOP:          "IFT_LOOP",
}
