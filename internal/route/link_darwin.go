package route

import "golang.org/x/sys/unix"

// bsdLinkKind returns the kind of a darwin interface of type ifType. utun
// and ipsec are IFT_OTHER and point-to-point.
func bsdLinkKind(ifType int, p2p bool) LinkKind {
	switch ifType {
	case unix.IFT_ETHER, unix.IFT_CELLULAR, unix.IFT_BRIDGE, unix.IFT_L2VLAN,
		unix.IFT_IEEE8023ADLAG:
		return LinkPhysical
	case unix.IFT_OTHER:
		if p2p {
			return LinkVPN
		}
	case unix.IFT_PPP:
		return LinkPPP
	case unix.IFT_GIF, unix.IFT_STF:
		return LinkIPTunnel
	case unix.IFT_LOOP:
		return LinkLoopback
	}
	return LinkUnknown
}

// bsdLinkTypeNames names the interface types of bsdLinkKind for logs.
var bsdLinkTypeNames = map[int]string{
	unix.IFT_ETHER:         "IFT_ETHER",
	unix.IFT_CELLULAR:      "IFT_CELLULAR",
	unix.IFT_BRIDGE:        "IFT_BRIDGE",
	unix.IFT_L2VLAN:        "IFT_L2VLAN",
	unix.IFT_IEEE8023ADLAG: "IFT_IEEE8023ADLAG",
	unix.IFT_OTHER:         "IFT_OTHER",
	unix.IFT_PPP:           "IFT_PPP",
	unix.IFT_GIF:           "IFT_GIF",
	unix.IFT_STF:           "IFT_STF",
	unix.IFT_LOOP:          "IFT_LOOP",
}
