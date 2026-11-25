package route

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Linux link constants (<linux/rtnetlink.h>, <linux/if_link.h>,
// <linux/if.h>, <linux/if_arp.h>); see netlink.go for why they are kept
// here.
const (
	rtmNewLink   = 16
	rtmGetLink   = 18
	ifinfomsgLen = 16

	iflaIfname   = 3
	iflaLinkinfo = 18
	iflaInfoKind = 1

	iffLoopback    = 0x8
	iffPointopoint = 0x10

	arphrdEther    = 1
	arphrdPPP      = 512
	arphrdRawIP    = 519
	arphrdTunnel   = 768
	arphrdTunnel6  = 769
	arphrdLoopback = 772
	arphrdSit      = 776
	arphrdIPGRE    = 778
	arphrdNone     = 0xfffe
)

// arphrdNames names the link types of linuxLinkInfo for logs.
var arphrdNames = map[uint16]string{
	arphrdEther:    "ARPHRD_ETHER",
	arphrdPPP:      "ARPHRD_PPP",
	arphrdRawIP:    "ARPHRD_RAWIP",
	arphrdTunnel:   "ARPHRD_TUNNEL",
	arphrdTunnel6:  "ARPHRD_TUNNEL6",
	arphrdLoopback: "ARPHRD_LOOPBACK",
	arphrdSit:      "ARPHRD_SIT",
	arphrdIPGRE:    "ARPHRD_IPGRE",
	arphrdNone:     "ARPHRD_NONE",
}

// Link kinds (IFLA_INFO_KIND) by LinkKind.
var (
	physicalLinkKinds = []string{
		"bond", "team", "bridge", "vlan", "macvlan", "macvtap", "ipvlan", "ipvtap",
		"veth", "wwan", "rmnet",
	}
	vpnLinkKinds = []string{
		"wireguard", "tun", "xfrm", "vti", "vti6", "ovpn", "ovpn-dco",
	}
	ipTunnelLinkKinds = []string{"sit", "ipip", "ip6tnl", "gre", "ip6gre"}
)

// netlinkLink is a decoded RTM_NEWLINK message.
type netlinkLink struct {
	index  int
	name   string
	arphrd uint16
	flags  uint32
	// kind is IFLA_INFO_KIND, empty for a link without a driver kind,
	// such as a plain Ethernet or Wi-Fi device.
	kind string
}

// encodeLinkGet returns an RTM_GETLINK request for the link with index.
func encodeLinkGet(seq uint32, index int) []byte {
	b := appendNetlinkHeader(nil, ifinfomsgLen, rtmGetLink, nlmFRequest, seq)
	b = append(b, 0, 0, 0, 0) // ifi_family, pad, ifi_type
	b = binary.NativeEndian.AppendUint32(b, uint32(int32(index)))
	return append(b, make([]byte, 8)...) // ifi_flags, ifi_change
}

// parseNetlinkLink decodes data, the payload of an RTM_NEWLINK message.
func parseNetlinkLink(data []byte) (netlinkLink, error) {
	if len(data) < ifinfomsgLen {
		return netlinkLink{}, errors.New("netlink: short link message")
	}
	l := netlinkLink{
		arphrd: binary.NativeEndian.Uint16(data[2:4]),
		index:  int(int32(binary.NativeEndian.Uint32(data[4:8]))),
		flags:  binary.NativeEndian.Uint32(data[8:12]),
	}
	var nestedErr error
	err := walkAttrs(data[ifinfomsgLen:], func(typ uint16, val []byte) {
		switch typ {
		case iflaIfname:
			l.name = netlinkString(val)
		case iflaLinkinfo:
			nestedErr = walkAttrs(val, func(typ uint16, val []byte) {
				if typ == iflaInfoKind {
					l.kind = netlinkString(val)
				}
			})
		}
	})
	return l, errors.Join(err, nestedErr)
}

// netlinkString returns b, a NUL-terminated netlink string, as a string.
func netlinkString(b []byte) string {
	return strings.TrimRight(string(b), "\x00")
}

// linuxLinkInfo returns the LinkInfo of l. A link without a kind is
// physical, unless it is PPP or loopback.
//
// The tun driver serves both TUN and TAP links under the kind "tun"; a TAP
// link is the one with an Ethernet link type. Both stay VPN links, since a
// TAP that carries the default route is almost always an L2 VPN (OpenVPN in
// TAP mode, ZeroTier, tinc), while a VM's TAP sits in a bridge. The detail
// says "tap" so that a misclassification is visible in the logs.
func linuxLinkInfo(l netlinkLink) LinkInfo {
	detail := "kind=" + l.kind
	if l.kind == "" {
		detail = arphrdName(l.arphrd)
	}
	if l.kind == "tun" && l.arphrd == arphrdEther {
		detail += " (tap)"
	}
	if l.flags&iffPointopoint != 0 {
		detail += " p2p"
	}
	return LinkInfo{
		Index:  l.index,
		Name:   l.name,
		Kind:   linuxLinkKind(l),
		Detail: detail,
	}
}

func linuxLinkKind(l netlinkLink) LinkKind {
	switch {
	case l.flags&iffLoopback != 0 || l.arphrd == arphrdLoopback:
		return LinkLoopback
	case l.kind == "ppp" || l.arphrd == arphrdPPP:
		return LinkPPP
	case l.kind == "":
		return LinkPhysical
	case slices.Contains(physicalLinkKinds, l.kind):
		return LinkPhysical
	case slices.Contains(vpnLinkKinds, l.kind):
		return LinkVPN
	case slices.Contains(ipTunnelLinkKinds, l.kind):
		return LinkIPTunnel
	default:
		return LinkUnknown
	}
}

// arphrdName returns the name of the link type t for logs.
func arphrdName(t uint16) string {
	if name, ok := arphrdNames[t]; ok {
		return name
	}
	return fmt.Sprintf("ARPHRD_%d", t)
}

// linkInfoFromNetlink reads the link with index from reply, the answer to
// encodeLinkGet.
func linkInfoFromNetlink(reply []netlinkMessage, index int) (LinkInfo, error) {
	if len(reply) != 1 || reply[0].typ != rtmNewLink {
		return LinkInfo{}, fmt.Errorf("link %d: no link in the reply", index)
	}
	l, err := parseNetlinkLink(reply[0].data)
	if err != nil {
		return LinkInfo{}, fmt.Errorf("link %d: %w", index, err)
	}
	if l.index != index {
		return LinkInfo{}, fmt.Errorf("link %d: reply for link %d", index, l.index)
	}
	return linuxLinkInfo(l), nil
}
