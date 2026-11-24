package netutil

import (
	"encoding/binary"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nlLink encodes an ifinfomsg of arphrd, index and flags, with the name
// and, when kind is not empty, IFLA_LINKINFO/IFLA_INFO_KIND.
func nlLink(arphrd uint16, index int, flags uint32, name, kind string) []byte {
	b := []byte{0, 0}
	b = binary.NativeEndian.AppendUint16(b, arphrd)
	b = binary.NativeEndian.AppendUint32(b, uint32(int32(index)))
	b = binary.NativeEndian.AppendUint32(b, flags)
	b = binary.NativeEndian.AppendUint32(b, 0)
	b = append(b, nlAttr(iflaIfname, append([]byte(name), 0))...)
	if kind != "" {
		info := nlAttr(iflaInfoKind, append([]byte(kind), 0))
		b = append(b, nlAttr(iflaLinkinfo|0x8000, info)...)
	}
	return b
}

func TestEncodeLinkGet(t *testing.T) {
	msgs, err := parseNetlinkMessages(encodeLinkGet(3, 7))
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	m := msgs[0]
	assert.Equal(t, uint16(rtmGetLink), m.typ)
	assert.Equal(t, uint16(nlmFRequest), m.flags)
	assert.Equal(t, uint32(3), m.seq)
	require.Len(t, m.data, ifinfomsgLen)
	assert.Equal(t, uint32(7), binary.NativeEndian.Uint32(m.data[4:8]))
}

func TestEncodeRouteDump(t *testing.T) {
	msgs, err := parseNetlinkMessages(encodeRouteDump(4, FamilyV6))
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	m := msgs[0]
	assert.Equal(t, uint16(rtmGetRoute), m.typ)
	assert.Equal(t, uint16(nlmFRequest|nlmFDump), m.flags)
	require.Len(t, m.data, rtmsgLen)
	assert.Equal(t, uint8(linuxAFInet6), m.data[0])
	assert.Equal(t, make([]byte, rtmsgLen-1), m.data[1:])
}

func TestLinkInfoFromNetlink(t *testing.T) {
	const up = 0x1
	tcs := []struct {
		name    string
		payload []byte
		want    LinkInfo
	}{
		{
			name:    "ethernet without kind is physical",
			payload: nlLink(arphrdEther, 2, up, "eth0", ""),
			want: LinkInfo{
				Index:  2,
				Name:   "eth0",
				Kind:   LinkPhysical,
				Detail: "ARPHRD_ETHER",
			},
		},
		{
			name:    "raw-ip modem without kind is physical",
			payload: nlLink(arphrdNone, 3, up|iffPointopoint, "wwan0", ""),
			want: LinkInfo{
				Index: 3, Name: "wwan0", Kind: LinkPhysical, Detail: "ARPHRD_NONE p2p",
			},
		},
		{
			name:    "rmnet is physical",
			payload: nlLink(arphrdRawIP, 4, up, "rmnet_data0", "rmnet"),
			want: LinkInfo{
				Index:  4,
				Name:   "rmnet_data0",
				Kind:   LinkPhysical,
				Detail: "kind=rmnet",
			},
		},
		{
			name:    "team is physical",
			payload: nlLink(arphrdEther, 15, up, "team0", "team"),
			want: LinkInfo{
				Index:  15,
				Name:   "team0",
				Kind:   LinkPhysical,
				Detail: "kind=team",
			},
		},
		{
			name:    "macvtap is physical",
			payload: nlLink(arphrdEther, 16, up, "macvtap0", "macvtap"),
			want: LinkInfo{
				Index: 16, Name: "macvtap0", Kind: LinkPhysical, Detail: "kind=macvtap",
			},
		},
		{
			name:    "ipvtap is physical",
			payload: nlLink(arphrdEther, 17, up, "ipvtap0", "ipvtap"),
			want: LinkInfo{
				Index: 17, Name: "ipvtap0", Kind: LinkPhysical, Detail: "kind=ipvtap",
			},
		},
		{
			name:    "ovpn-dco is vpn",
			payload: nlLink(arphrdNone, 18, up|iffPointopoint, "tun1", "ovpn-dco"),
			want: LinkInfo{
				Index: 18, Name: "tun1", Kind: LinkVPN, Detail: "kind=ovpn-dco p2p",
			},
		},
		{
			name:    "bridge is physical",
			payload: nlLink(arphrdEther, 5, up, "br0", "bridge"),
			want: LinkInfo{
				Index:  5,
				Name:   "br0",
				Kind:   LinkPhysical,
				Detail: "kind=bridge",
			},
		},
		{
			name:    "wireguard is vpn",
			payload: nlLink(arphrdNone, 7, up|iffPointopoint, "wg0", "wireguard"),
			want: LinkInfo{
				Index: 7, Name: "wg0", Kind: LinkVPN, Detail: "kind=wireguard p2p",
			},
		},
		{
			name:    "tun is vpn",
			payload: nlLink(arphrdNone, 8, up|iffPointopoint, "tun0", "tun"),
			want:    LinkInfo{Index: 8, Name: "tun0", Kind: LinkVPN, Detail: "kind=tun p2p"},
		},
		{
			name:    "tap is vpn",
			payload: nlLink(arphrdEther, 19, up, "tap0", "tun"),
			want: LinkInfo{
				Index:  19,
				Name:   "tap0",
				Kind:   LinkVPN,
				Detail: "kind=tun (tap)",
			},
		},
		{
			name:    "ppp kind",
			payload: nlLink(arphrdPPP, 9, up|iffPointopoint, "ppp0", "ppp"),
			want:    LinkInfo{Index: 9, Name: "ppp0", Kind: LinkPPP, Detail: "kind=ppp p2p"},
		},
		{
			name:    "ppp link type without kind",
			payload: nlLink(arphrdPPP, 10, up|iffPointopoint, "ppp1", ""),
			want: LinkInfo{
				Index:  10,
				Name:   "ppp1",
				Kind:   LinkPPP,
				Detail: "ARPHRD_PPP p2p",
			},
		},
		{
			name:    "sit is an ip tunnel",
			payload: nlLink(arphrdSit, 11, up, "sit1", "sit"),
			want: LinkInfo{
				Index:  11,
				Name:   "sit1",
				Kind:   LinkIPTunnel,
				Detail: "kind=sit",
			},
		},
		{
			name:    "gre is an ip tunnel",
			payload: nlLink(arphrdIPGRE, 12, up, "gre1", "gre"),
			want: LinkInfo{
				Index:  12,
				Name:   "gre1",
				Kind:   LinkIPTunnel,
				Detail: "kind=gre",
			},
		},
		{
			name:    "unlisted kind is unknown",
			payload: nlLink(arphrdEther, 13, up, "dummy0", "dummy"),
			want: LinkInfo{
				Index:  13,
				Name:   "dummy0",
				Kind:   LinkUnknown,
				Detail: "kind=dummy",
			},
		},
		{
			name:    "loopback",
			payload: nlLink(arphrdLoopback, 1, up|iffLoopback, "lo", ""),
			want: LinkInfo{
				Index:  1,
				Name:   "lo",
				Kind:   LinkLoopback,
				Detail: "ARPHRD_LOOPBACK",
			},
		},
		{
			name:    "unnamed link type",
			payload: nlLink(32, 14, up, "ib0", ""),
			want: LinkInfo{
				Index:  14,
				Name:   "ib0",
				Kind:   LinkPhysical,
				Detail: "ARPHRD_32",
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			reply := []netlinkMessage{{typ: rtmNewLink, data: tc.payload}}
			got, err := linkInfoFromNetlink(reply, tc.want.Index)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestLinkInfoFromNetlink_Errors(t *testing.T) {
	eth0 := nlLink(arphrdEther, 2, 0, "eth0", "")
	tcs := []struct {
		name    string
		reply   []netlinkMessage
		wantMsg string
	}{
		{name: "no message", wantMsg: "no link in the reply"},
		{
			name:    "not a link message",
			reply:   []netlinkMessage{{typ: rtmNewRoute, data: eth0}},
			wantMsg: "no link in the reply",
		},
		{
			name: "other link",
			reply: []netlinkMessage{
				{typ: rtmNewLink, data: nlLink(arphrdEther, 3, 0, "eth1", "")},
			},
			wantMsg: "reply for link 3",
		},
		{
			name:    "short message",
			reply:   []netlinkMessage{{typ: rtmNewLink, data: eth0[:8]}},
			wantMsg: "short link message",
		},
		{
			name: "bad nested attribute",
			reply: []netlinkMessage{{typ: rtmNewLink, data: append(
				nlLink(arphrdEther, 2, 0, "eth0", ""),
				nlAttr(iflaLinkinfo, []byte{0xff, 0, 1, 0})...,
			)}},
			wantMsg: "bad attribute",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			_, err := linkInfoFromNetlink(tc.reply, 2)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantMsg)
		})
	}
}

// nlNexthop encodes an rtnexthop entry for oif with RTNH_F_* flags and a
// gateway attribute.
func nlNexthop(oif int, flags uint8, gateway string) []byte {
	gw := nlAttr(rtaGateway, nlAddr(gateway))
	b := binary.NativeEndian.AppendUint16(nil, uint16(8+len(gw)))
	b = append(b, flags, 0)
	b = binary.NativeEndian.AppendUint32(b, uint32(int32(oif)))
	return append(b, gw...)
}

func TestDefaultRouteOifs(t *testing.T) {
	route := func(family, dstLen, table, typ uint8, attrs ...[]byte) netlinkMessage {
		return netlinkMessage{
			typ:  rtmNewRoute,
			data: nlRoute(family, dstLen, table, typ, attrs...),
		}
	}
	oif := func(i uint32) []byte { return nlAttr(rtaOif, nlU32(i)) }
	deadRoute := func(i uint32, flags uint32) netlinkMessage {
		m := route(linuxAFInet, 0, 254, rtnUnicast, oif(i))
		binary.NativeEndian.PutUint32(m.data[8:12], flags)
		return m
	}

	reply := []netlinkMessage{
		// wg-quick: the default in table 51820 and the one in main.
		route(linuxAFInet, 0, 252, rtnUnicast, nlAttr(rtaTable, nlU32(51820)), oif(7)),
		route(linuxAFInet, 0, 254, rtnUnicast,
			nlAttr(rtaGateway, nlAddr("10.0.2.2")), oif(2)),
		// A duplicate in another table.
		route(linuxAFInet, 0, 100, rtnUnicast, oif(2)),
		// A multipath default with a dead and a link-down next hop.
		route(linuxAFInet, 0, 254, rtnUnicast, nlAttr(rtaMultipath, slices.Concat(
			nlNexthop(3, 0, "10.0.3.1"),
			nlNexthop(11, rtnhFDead, "10.0.11.1"),
			nlNexthop(4, 0, "10.0.4.1"),
			nlNexthop(12, rtnhFLinkdown, "10.0.12.1"),
		))),
		// Single-path defaults that are dead or link-down.
		deadRoute(13, rtnhFDead),
		deadRoute(14, rtnhFLinkdown|rtnhFDead),
		// Not defaults.
		route(linuxAFInet, 24, 254, rtnUnicast, oif(5)),
		route(linuxAFInet, 0, 254, rtnUnreachable, oif(1)),
		route(linuxAFInet, 0, 254, rtnUnicast),
		{typ: nlmsgDone},
		// IPv6.
		route(
			linuxAFInet6,
			0,
			254,
			rtnUnicast,
			nlAttr(rtaGateway, nlAddr("fe80::1")),
			oif(2),
		),
	}

	got, err := defaultRouteOifs(reply, FamilyV4)
	require.NoError(t, err)
	assert.Equal(t, []int{7, 2, 3, 4}, got)

	got, err = defaultRouteOifs(reply, FamilyV6)
	require.NoError(t, err)
	assert.Equal(t, []int{2}, got)

	_, err = defaultRouteOifs(
		[]netlinkMessage{{typ: rtmNewRoute, data: []byte{1}}},
		FamilyV4,
	)
	assert.Error(t, err)
}
