package route

import (
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBSDLinkKind_FreeBSD(t *testing.T) {
	tcs := []struct {
		name   string
		ifType int
		p2p    bool
		want   LinkKind
	}{
		{name: "ethernet", ifType: syscall.IFT_ETHER, want: LinkPhysical},
		{name: "tap is ethernet", ifType: syscall.IFT_ETHER, want: LinkPhysical},
		{name: "bridge", ifType: syscall.IFT_BRIDGE, want: LinkPhysical},
		{name: "vlan", ifType: syscall.IFT_L2VLAN, want: LinkPhysical},
		{name: "lacp", ifType: syscall.IFT_IEEE8023ADLAG, want: LinkPhysical},
		{name: "mbim modem", ifType: ifTypeMBIM, want: LinkPhysical},
		{name: "wireguard", ifType: ifTypeWireGuard, want: LinkVPN},
		{
			name:   "tun is ppp and ambiguous",
			ifType: syscall.IFT_PPP,
			p2p:    true,
			want:   LinkPPP,
		},
		{name: "gif", ifType: syscall.IFT_GIF, p2p: true, want: LinkIPTunnel},
		{name: "gre or ovpn", ifType: syscall.IFT_TUNNEL, p2p: true, want: LinkIPTunnel},
		{name: "stf", ifType: syscall.IFT_STF, want: LinkIPTunnel},
		{name: "loopback", ifType: syscall.IFT_LOOP, want: LinkLoopback},
		{
			name:   "propvirtual is unknown",
			ifType: syscall.IFT_PROPVIRTUAL,
			p2p:    true,
			want:   LinkUnknown,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, bsdLinkKind(tc.ifType, tc.p2p))
		})
	}
}
