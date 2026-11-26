package capture

import (
	"net"
	"testing"

	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeLinkType(t *testing.T) {
	tcs := []struct {
		name string
		in   layers.LinkType
		want layers.LinkType
	}{
		{"BSD DLT_RAW becomes Raw", 12, layers.LinkTypeRaw},
		{"PPP in HDLC framing becomes PPP", 50, layers.LinkTypePPP},
		{"Raw is kept", layers.LinkTypeRaw, layers.LinkTypeRaw},
		{"PPP is kept", layers.LinkTypePPP, layers.LinkTypePPP},
		{"Ethernet is kept", layers.LinkTypeEthernet, layers.LinkTypeEthernet},
		{"Null is kept", layers.LinkTypeNull, layers.LinkTypeNull},
		{"an unknown type is kept", layers.LinkTypeLinuxSLL, layers.LinkTypeLinuxSLL},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, normalizeLinkType(tc.in))
		})
	}
}

// A normalized link type is one the filters support.
func TestNormalizeLinkType_FiltersSupportIt(t *testing.T) {
	for _, lt := range []layers.LinkType{12, 50} {
		_, err := SynAckFilter(normalizeLinkType(lt))
		assert.NoError(t, err, lt)
	}
}

// The HDLC marker check jumps over the HDLC framing's program with an
// 8-bit offset: a program of 255 instructions is the longest it can skip.
func TestBuildForLink_PPPJumpLimit(t *testing.T) {
	ret := BPFInstruction{Op: 0x06} // ret #0
	programOf := func(n int) func(linkLayout) []BPFInstruction {
		return func(linkLayout) []BPFInstruction {
			prog := make([]BPFInstruction, n)
			for i := range prog {
				prog[i] = ret
			}
			return prog
		}
	}

	prog, err := buildForLink(layers.LinkTypePPP, programOf(255))
	require.NoError(t, err)
	assert.Equal(t, uint8(255), prog[1].Jf)
	assert.Len(t, prog, 2+2*255)

	_, err = buildForLink(layers.LinkTypePPP, programOf(256))
	assert.EqualError(t, err,
		"PPP HDLC filter has 256 instructions, more than a BPF jump can skip (255)")
}

func TestLinuxLinkType(t *testing.T) {
	mac := net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	tcs := []struct {
		name         string
		flags        net.Flags
		hardwareAddr net.HardwareAddr
		want         layers.LinkType
	}{
		{
			"loopback without an address is Ethernet",
			net.FlagUp | net.FlagLoopback, nil, layers.LinkTypeEthernet,
		},
		{"Ethernet with an address", net.FlagUp, mac, layers.LinkTypeEthernet},
		{"TUN without an address is Raw", net.FlagUp, nil, layers.LinkTypeRaw},
		{
			"loopback with an address is Ethernet",
			net.FlagUp | net.FlagLoopback, mac, layers.LinkTypeEthernet,
		},
		{
			"point-to-point is Raw",
			net.FlagUp | net.FlagPointToPoint, mac, layers.LinkTypeRaw,
		},
		{
			"point-to-point without an address is Raw",
			net.FlagUp | net.FlagPointToPoint, nil, layers.LinkTypeRaw,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, linuxLinkType(tc.flags, tc.hardwareAddr))
		})
	}
}
