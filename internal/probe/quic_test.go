package probe

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// versionNegotiation builds a Version Negotiation packet with the given
// connection IDs and versions.
func versionNegotiation(dcid, scid []byte, versions ...uint32) []byte {
	b := []byte{0x80 | 0x40, 0, 0, 0, 0}
	b = append(b, byte(len(dcid)))
	b = append(b, dcid...)
	b = append(b, byte(len(scid)))
	b = append(b, scid...)
	for _, v := range versions {
		b = binary.BigEndian.AppendUint32(b, v)
	}
	return b
}

func TestNewQUICRequest(t *testing.T) {
	req, dcid, scid := newQUICRequest()
	require.Len(t, req, 1200)
	assert.Equal(t, byte(0xC0), req[0])
	version := binary.BigEndian.Uint32(req[1:5])
	assert.Equal(
		t,
		uint32(0x0A0A0A0A),
		version&0x0F0F0F0F,
		"reserved version %#x",
		version,
	)
	assert.Equal(t, byte(8), req[5])
	assert.Equal(t, dcid, req[6:14])
	assert.Equal(t, byte(8), req[14])
	assert.Equal(t, scid, req[15:23])
	assert.Equal(t, make([]byte, 1200-23), req[23:], "zero padding")

	req2, dcid2, scid2 := newQUICRequest()
	assert.NotEqual(t, dcid, dcid2)
	assert.NotEqual(t, scid, scid2)
	assert.NotEqual(t, req, req2)
}

func TestIsVersionNegotiation(t *testing.T) {
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	scid := []byte{9, 10, 11, 12, 13, 14, 15, 16}
	other := []byte{0, 0, 0, 0, 0, 0, 0, 1}

	valid := versionNegotiation(scid, dcid, 1, 0x6b3343cf)
	assert.True(t, isVersionNegotiation(valid, dcid, scid))

	nonZero := bytes.Clone(valid)
	nonZero[4] = 1
	for name, b := range map[string][]byte{
		"wrong destination":  versionNegotiation(other, dcid, 1),
		"wrong source":       versionNegotiation(scid, other, 1),
		"CIDs not swapped":   versionNegotiation(dcid, scid, 1),
		"no versions":        versionNegotiation(scid, dcid),
		"partial version":    append(versionNegotiation(scid, dcid, 1), 0, 0),
		"non-zero version":   nonZero,
		"short header":       {0x80, 0, 0, 0},
		"short packet":       valid[:10],
		"truncated CID":      valid[:6+4],
		"short header bit 0": append([]byte{0x40}, valid[1:]...),
		"empty":              nil,
	} {
		assert.False(t, isVersionNegotiation(b, dcid, scid), name)
	}
}
