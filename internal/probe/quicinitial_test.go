package probe

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/proto"
)

// helloExtensions returns the extensions of the ClientHello handshake
// message hello, by type.
func helloExtensions(t *testing.T, hello []byte) map[uint16][]byte {
	t.Helper()
	// type 1, length 3, version 2, random 32
	b := hello[4+2+32:]
	skip := func(lenBytes int) {
		n := 0
		for _, c := range b[:lenBytes] {
			n = n<<8 | int(c)
		}
		b = b[lenBytes+n:]
	}
	skip(1) // session ID
	skip(2) // cipher suites
	skip(1) // compression methods
	exts := map[uint16][]byte{}
	b = b[2:]
	for len(b) >= 4 {
		typ := binary.BigEndian.Uint16(b)
		n := int(binary.BigEndian.Uint16(b[2:]))
		exts[typ] = b[4 : 4+n]
		b = b[4+n:]
	}
	require.Empty(t, b, "the extensions fill the ClientHello")
	return exts
}

// transportParameters returns the transport parameters of the
// quic_transport_parameters extension ext, by ID.
func transportParameters(t *testing.T, ext []byte) map[uint64][]byte {
	t.Helper()
	params := map[uint64][]byte{}
	for len(ext) > 0 {
		id, n, err := proto.ReadQUICVarint(ext)
		require.NoError(t, err)
		ext = ext[n:]
		l, n, err := proto.ReadQUICVarint(ext)
		require.NoError(t, err)
		ext = ext[n:]
		params[id] = ext[:l]
		ext = ext[l:]
	}
	return params
}

func TestBuildQUICClientHello(t *testing.T) {
	scid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	hello, err := buildQUICClientHello("www.example.org", scid)
	require.NoError(t, err)
	require.Equal(t, byte(0x01), hello[0], "a ClientHello handshake message")
	assert.Equal(t, len(hello)-4, int(hello[1])<<16|int(hello[2])<<8|int(hello[3]),
		"one whole message")

	record := append([]byte{0x16, 0x03, 0x01, byte(len(hello) >> 8), byte(len(hello))},
		hello...)
	start, end, err := proto.NewFakeTLSMessage(record).ExtractSNIOffset()
	require.NoError(t, err)
	assert.Equal(t, "www.example.org", string(record[start:end]))

	exts := helloExtensions(t, hello)
	assert.Equal(t, []byte{0, 3, 2, 'h', '3'}, exts[0x0010], "ALPN h3 only")
	require.Contains(t, exts, uint16(0x0039), "quic_transport_parameters")
	params := transportParameters(t, exts[0x0039])
	assert.Equal(t, scid, params[proto.QUICTPInitialSourceConnectionID])
	assert.Equal(t, []byte{0x80, 0x10, 0x00, 0x00}, params[proto.QUICTPInitialMaxData])
	// key_share: one X25519 share (group 0x001d, 32 bytes).
	assert.Equal(t, []byte{0x00, 0x1d, 0x00, 0x20}, exts[0x0033][2:6])
	assert.Len(t, exts[0x0033], 2+4+32, "one key share")
}

func TestBuildQUICClientHello_IPLiteral(t *testing.T) {
	hello, err := buildQUICClientHello("192.0.2.1", []byte{1})
	require.NoError(t, err)
	assert.NotContains(t, helloExtensions(t, hello), uint16(0x0000), "no SNI")
}

func TestNewQUICInitial(t *testing.T) {
	pkt, dcid, scid, err := newQUICInitial("www.example.org")
	require.NoError(t, err)
	assert.Len(t, pkt, proto.QUICMinInitialSize)
	h, err := proto.ParseQUICLongHeader(pkt)
	require.NoError(t, err)
	assert.Equal(t, proto.QUICInitial, h.Type)
	assert.Equal(t, proto.QUICVersion1, h.Version)
	assert.Equal(t, dcid, h.DCID)
	assert.Equal(t, scid, h.SCID)
	assert.Len(t, dcid, quicInitialCIDLen)
	assert.Len(t, scid, quicInitialCIDLen)

	_, dcid2, scid2, err := newQUICInitial("www.example.org")
	require.NoError(t, err)
	assert.False(t, bytes.Equal(dcid, dcid2), "fresh DCIDs")
	assert.False(t, bytes.Equal(scid, scid2), "fresh SCIDs")
}

func TestNewQUICInitial_LongName(t *testing.T) {
	// A host name of 253 bytes still fits one Initial.
	label := bytes.Repeat([]byte("a"), 63)
	host := string(bytes.Join([][]byte{label, label, label, label[:61]}, []byte(".")))
	require.Len(t, host, 253)
	pkt, _, _, err := newQUICInitial(host)
	require.NoError(t, err)
	assert.Len(t, pkt, proto.QUICMinInitialSize)
}
