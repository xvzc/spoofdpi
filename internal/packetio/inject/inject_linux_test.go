//go:build linux

package inject

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestIPv4Header_NetworkByteOrder(t *testing.T) {
	p := Packet{
		Src:      netip.MustParseAddr("192.0.2.1"),
		Dst:      netip.MustParseAddr("203.0.113.9"),
		Proto:    protoTCP,
		HopLimit: 3,
		L4:       make([]byte, 0x0123),
	}
	b, err := ipv4Header(p).Marshal()
	require.NoError(t, err)
	require.Len(t, b, 20)
	assert.Equal(t, uint16(20+0x0123), binary.BigEndian.Uint16(b[2:4]), "ip_len")
	assert.Zero(t, binary.BigEndian.Uint16(b[4:6]), "an ID for the kernel to fill")
	assert.Zero(t, binary.BigEndian.Uint16(b[6:8]), "ip_off, without DF")
	assert.Zero(t, binary.BigEndian.Uint16(b[10:12]), "a checksum for the kernel to fill")
}

func TestIPv4Control_PacketInfo(t *testing.T) {
	p := Packet{
		Src:      netip.MustParseAddr("192.0.2.1"),
		Dst:      netip.MustParseAddr("203.0.113.9"),
		Proto:    protoTCP,
		HopLimit: 3,
	}
	msgs, err := unix.ParseSocketControlMessage(ipv4Control(p).Marshal())
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	assert.Equal(t, int32(unix.IPPROTO_IP), msgs[0].Header.Level)
	assert.Equal(t, int32(unix.IP_PKTINFO), msgs[0].Header.Type)

	// struct in_pktinfo: ipi_ifindex, ipi_spec_dst, ipi_addr.
	data := msgs[0].Data
	require.Len(t, data, unix.SizeofInet4Pktinfo)
	assert.Zero(t, binary.NativeEndian.Uint32(data[0:4]),
		"no interface, so the socket's bound one stays")
	assert.Equal(
		t,
		[]byte{192, 0, 2, 1},
		data[4:8],
		"ipi_spec_dst, the source to route with",
	)
}
