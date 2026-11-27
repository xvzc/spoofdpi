package route

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// parseOneRequest parses b, an encoded request, as exactly one netlink
// message whose length field covers all of b.
func parseOneRequest(t *testing.T, b []byte) netlinkMessage {
	t.Helper()
	msgs, err := parseNetlinkMessages(b)
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	assert.Equal(t, len(b), int(binary.NativeEndian.Uint32(b[0:4])))
	return msgs[0]
}

const (
	addFlags = nlmFRequest | nlmFAck | nlmFCreate | nlmFExcl
	delFlags = nlmFRequest | nlmFAck
)

func TestEncodeAddrModify(t *testing.T) {
	tcs := []struct {
		name      string
		addr      InterfaceAddr
		add       bool
		wantTyp   uint16
		wantFlags uint16
		wantHdr   []byte
		wantAttrs []byte
	}{
		{
			name: "add ipv4 with peer",
			addr: InterfaceAddr{
				Index:     7,
				Local:     netip.MustParseAddr("10.200.0.1"),
				Peer:      netip.MustParseAddr("10.200.0.2"),
				PrefixLen: 32,
			},
			add:       true,
			wantTyp:   rtmNewAddr,
			wantFlags: addFlags,
			wantHdr:   append([]byte{linuxAFInet, 32, 0, 0}, nlU32(7)...),
			wantAttrs: append(
				nlAttr(ifaLocal, nlAddr("10.200.0.1")),
				nlAttr(ifaAddress, nlAddr("10.200.0.2"))...,
			),
		},
		{
			name: "delete ipv4 without peer",
			addr: InterfaceAddr{
				Index:     3,
				Local:     netip.MustParseAddr("192.0.2.1"),
				PrefixLen: 24,
			},
			wantTyp:   rtmDelAddr,
			wantFlags: delFlags,
			wantHdr:   append([]byte{linuxAFInet, 24, 0, 0}, nlU32(3)...),
			wantAttrs: append(
				nlAttr(ifaLocal, nlAddr("192.0.2.1")),
				nlAttr(ifaAddress, nlAddr("192.0.2.1"))...,
			),
		},
		{
			name: "add ipv6",
			addr: InterfaceAddr{
				Index:     4,
				Local:     netip.MustParseAddr("fd00::1"),
				PrefixLen: 64,
			},
			add:       true,
			wantTyp:   rtmNewAddr,
			wantFlags: addFlags,
			wantHdr:   append([]byte{linuxAFInet6, 64, 0, 0}, nlU32(4)...),
			wantAttrs: append(
				nlAttr(ifaLocal, nlAddr("fd00::1")),
				nlAttr(ifaAddress, nlAddr("fd00::1"))...,
			),
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			m := parseOneRequest(t, encodeAddrModify(9, tc.addr, tc.add))
			assert.Equal(t, tc.wantTyp, m.typ)
			assert.Equal(t, tc.wantFlags, m.flags)
			assert.Equal(t, uint32(9), m.seq)
			require.GreaterOrEqual(t, len(m.data), ifaddrmsgLen)
			assert.Equal(t, tc.wantHdr, m.data[:ifaddrmsgLen])
			assert.Equal(t, tc.wantAttrs, m.data[ifaddrmsgLen:])
		})
	}
}

func TestEncodeLinkSetUp(t *testing.T) {
	tcs := []struct {
		name      string
		up        bool
		wantFlags uint32
	}{
		{name: "up", up: true, wantFlags: iffUp},
		{name: "down", up: false, wantFlags: 0},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			m := parseOneRequest(t, encodeLinkSetUp(5, 12, tc.up))
			assert.Equal(t, uint16(rtmNewLink), m.typ)
			assert.Equal(t, uint16(delFlags), m.flags, "no create for an existing link")
			assert.Equal(t, uint32(5), m.seq)
			require.Len(t, m.data, ifinfomsgLen)
			assert.Equal(t, []byte{0, 0, 0, 0}, m.data[0:4])
			assert.Equal(t, uint32(12), binary.NativeEndian.Uint32(m.data[4:8]))
			assert.Equal(t, tc.wantFlags, binary.NativeEndian.Uint32(m.data[8:12]))
			assert.Equal(t, uint32(iffUp), binary.NativeEndian.Uint32(m.data[12:16]),
				"only IFF_UP changes")
		})
	}
}

func TestInterfaceAddrString(t *testing.T) {
	assert.Equal(t, "10.200.0.1 peer 10.200.0.2/32 dev 7", InterfaceAddr{
		Index:     7,
		Local:     netip.MustParseAddr("10.200.0.1"),
		Peer:      netip.MustParseAddr("10.200.0.2"),
		PrefixLen: 32,
	}.String())
	assert.Equal(t, "192.0.2.1/24 dev 3", InterfaceAddr{
		Index:     3,
		Local:     netip.MustParseAddr("192.0.2.1"),
		PrefixLen: 24,
	}.String())
}
