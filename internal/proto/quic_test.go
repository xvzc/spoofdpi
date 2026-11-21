package proto

import (
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The sample packets of RFC 9001, Appendix A.

const rfc9001DCID = "8394c8f03e515708"

const rfc9001A2Crypto = "" +
	"060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868" +
	"04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578" +
	"616d706c652e636f6dff01000100000a00080006001d00170018001000070005" +
	"04616c706e000500050100000000003300260024001d00209370b2c9caa47fba" +
	"baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400" +
	"0d0010000e0403050306030203080408050806002d00020101001c0002400100" +
	"3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000" +
	"75300901100f088394c8f03e51570806048000ffff"

const rfc9001A2Packet = "" +
	"c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11" +
	"d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399" +
	"1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c" +
	"8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212" +
	"30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5" +
	"457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208" +
	"4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec" +
	"4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3" +
	"485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db" +
	"059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c" +
	"7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f8" +
	"9937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556" +
	"be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c74" +
	"68449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663a" +
	"c69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00" +
	"f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632" +
	"291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe58964" +
	"25c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd" +
	"14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ff" +
	"ef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198" +
	"e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd" +
	"c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73" +
	"203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77f" +
	"cb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e" +
	"fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade" +
	"a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e724047" +
	"90a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2" +
	"162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f4" +
	"40591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca0" +
	"6948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e" +
	"8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0" +
	"be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f09400" +
	"54da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab" +
	"760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9" +
	"f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4" +
	"056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064" +
	"7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241" +
	"e221af44860018ab0856972e194cd934"

const rfc9001A3Payload = "" +
	"02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf739" +
	"88cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c94" +
	"0d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00" +
	"020304"

const rfc9001A3Packet = "" +
	"cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a" +
	"5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3" +
	"dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84" +
	"022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc4" +
	"2158407dd074ee"

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func TestQUICInitialKeysFor(t *testing.T) {
	dcid := unhex(t, rfc9001DCID)

	client, err := QUICInitialKeysFor(dcid, false)
	require.NoError(t, err)
	assert.Equal(t, QUICInitialKeys{
		Key: unhex(t, "1f369613dd76d5467730efcbe3b1a22d"),
		IV:  unhex(t, "fa044b2f42a3fd3b46fb255c"),
		HP:  unhex(t, "9f50449e04a0e810283a1e9933adedd2"),
	}, client)

	server, err := QUICInitialKeysFor(dcid, true)
	require.NoError(t, err)
	assert.Equal(t, QUICInitialKeys{
		Key: unhex(t, "cf3a5331653c364c88f0f379b6067e37"),
		IV:  unhex(t, "0ac1493ca1905853b0bba03e"),
		HP:  unhex(t, "c206b8d9b9f0f37644430b490eeaa314"),
	}, server)
}

func TestSealQUICInitial_ClientSample(t *testing.T) {
	dcid := unhex(t, rfc9001DCID)
	keys, err := QUICInitialKeysFor(dcid, false)
	require.NoError(t, err)

	got, err := SealQUICInitial(QUICInitialPacket{
		DCID:         dcid,
		PacketNumber: 2,
		PNLen:        4,
		Payload:      unhex(t, rfc9001A2Crypto),
	}, keys, QUICMinInitialSize)
	require.NoError(t, err)
	assert.Equal(t, rfc9001A2Packet, hex.EncodeToString(got))
}

func TestSealQUICInitial_ServerSample(t *testing.T) {
	keys, err := QUICInitialKeysFor(unhex(t, rfc9001DCID), true)
	require.NoError(t, err)

	got, err := SealQUICInitial(QUICInitialPacket{
		SCID:         unhex(t, "f067a5502a4262b5"),
		PacketNumber: 1,
		PNLen:        2,
		Payload:      unhex(t, rfc9001A3Payload),
	}, keys, 0)
	require.NoError(t, err)
	assert.Equal(t, rfc9001A3Packet, hex.EncodeToString(got))
}

func TestSealQUICInitial_Padding(t *testing.T) {
	keys, err := QUICInitialKeysFor([]byte{1, 2, 3, 4, 5, 6, 7, 8}, false)
	require.NoError(t, err)
	p := QUICInitialPacket{
		DCID:    []byte{1, 2, 3, 4, 5, 6, 7, 8},
		SCID:    []byte{9, 10, 11, 12},
		PNLen:   1,
		Payload: []byte{0x01}, // PING
	}

	got, err := SealQUICInitial(p, keys, 1200)
	require.NoError(t, err)
	assert.Len(t, got, 1200, "padded to padTo")

	// header: 1 + 4 + 1+8 + 1+4 + 1 (token length) + 2 (length) = 22,
	// then the packet number at 22; the sample is at 26 to 42.
	got, err = SealQUICInitial(p, keys, 0)
	require.NoError(t, err)
	assert.Len(t, got, 22+4+quicSampleLen, "room for the sample")
	length, _, err := ReadQUICVarint(got[20:])
	require.NoError(t, err)
	assert.Equal(t, uint64(len(got)-22), length, "Length covers the rest")

	big := p
	big.Payload = make([]byte, 1300)
	got, err = SealQUICInitial(big, keys, 1200)
	require.NoError(t, err)
	assert.Greater(t, len(got), 1200, "a longer packet is not cut")

	bad := p
	bad.PNLen = 5
	_, err = SealQUICInitial(bad, keys, 0)
	assert.Error(t, err)
	bad = p
	bad.Payload = make([]byte, 1<<14)
	_, err = SealQUICInitial(bad, keys, 0)
	assert.Error(t, err, "Length does not fit 2 bytes")
}

func TestQUICVarint(t *testing.T) {
	for _, tc := range []struct {
		v   uint64
		len int
	}{
		{0, 1},
		{63, 1},
		{64, 2},
		{16383, 2},
		{16384, 4},
		{1<<30 - 1, 4},
		{1 << 30, 8},
		{1<<62 - 1, 8},
	} {
		b := AppendQUICVarint([]byte{0xff}, tc.v)
		assert.Len(t, b, 1+tc.len, "%d", tc.v)
		v, n, err := ReadQUICVarint(b[1:])
		require.NoError(t, err)
		assert.Equal(t, tc.v, v)
		assert.Equal(t, tc.len, n)
	}
	// RFC 9000, appendix A.1.
	v, n, err := ReadQUICVarint(unhex(t, "c2197c5eff14e88c"))
	require.NoError(t, err)
	assert.Equal(t, uint64(151288809941952652), v)
	assert.Equal(t, 8, n)

	assert.Panics(t, func() { AppendQUICVarint(nil, 1<<62) })
	_, _, err = ReadQUICVarint(nil)
	assert.Error(t, err)
	_, _, err = ReadQUICVarint([]byte{0x40})
	assert.Error(t, err, "truncated")
}

func TestAppendQUICFrames(t *testing.T) {
	assert.Equal(t,
		[]byte{0x06, 0x00, 0x03, 'a', 'b', 'c'},
		AppendQUICCryptoFrame(nil, 0, []byte("abc")))
	assert.Equal(
		t,
		[]byte{0x0f, 0x02, 0xaa, 0xbb},
		AppendQUICTransportParameter(
			nil,
			QUICTPInitialSourceConnectionID,
			[]byte{0xaa, 0xbb},
		),
	)
	assert.Equal(t,
		[]byte{0x01, 0x02, 0x40, 0x64},
		AppendQUICTransportParameter(nil, QUICTPMaxIdleTimeout, AppendQUICVarint(nil, 100)))
}

func TestParseQUICLongHeader(t *testing.T) {
	h, err := ParseQUICLongHeader(unhex(t, rfc9001A2Packet))
	require.NoError(t, err)
	assert.Equal(t, QUICLongHeader{
		Type:    QUICInitial,
		Version: QUICVersion1,
		DCID:    unhex(t, rfc9001DCID),
		SCID:    []byte{},
	}, h)

	h, err = ParseQUICLongHeader(unhex(t, rfc9001A3Packet))
	require.NoError(t, err)
	assert.Equal(t, QUICLongHeader{
		Type:    QUICInitial,
		Version: QUICVersion1,
		DCID:    []byte{},
		SCID:    unhex(t, "f067a5502a4262b5"),
	}, h)

	// RFC 9001, appendix A.4.
	h, err = ParseQUICLongHeader(unhex(t, ""+
		"ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba"))
	require.NoError(t, err)
	assert.Equal(t, QUICRetry, h.Type)
	assert.Equal(t, unhex(t, "f067a5502a4262b5"), h.SCID)

	handshake := unhex(t, rfc9001A3Packet)
	handshake[0] = 0xe0 // type bits 0b10
	h, err = ParseQUICLongHeader(handshake)
	require.NoError(t, err)
	assert.Equal(t, QUICHandshake, h.Type)

	vn := []byte{0x80, 0, 0, 0, 0, 2, 0xaa, 0xbb, 1, 0xcc}
	vn = binary.BigEndian.AppendUint32(vn, QUICVersion1)
	vn = binary.BigEndian.AppendUint32(vn, 0x6b3343cf)
	h, err = ParseQUICLongHeader(vn)
	require.NoError(t, err)
	assert.Equal(t, QUICLongHeader{
		Type:              QUICVersionNegotiation,
		DCID:              []byte{0xaa, 0xbb},
		SCID:              []byte{0xcc},
		SupportedVersions: []uint32{QUICVersion1, 0x6b3343cf},
	}, h)

	other := []byte{0xc0, 0x6b, 0x33, 0x43, 0xcf, 0, 0}
	h, err = ParseQUICLongHeader(other)
	require.NoError(t, err)
	assert.Equal(t, uint32(0x6b3343cf), h.Version, "other versions parse their CIDs")

	long := append([]byte{0xc0, 0, 0, 0, 1, 21}, make([]byte, 21)...)
	long = append(long, 0, 0, 0)
	for name, b := range map[string][]byte{
		"empty":           nil,
		"short header":    {0x40, 1, 2, 3, 4, 5, 6, 7},
		"truncated DCID":  {0xc0, 0, 0, 0, 1, 8, 1, 2},
		"truncated SCID":  {0xc0, 0, 0, 0, 1, 0, 8, 1},
		"no payload":      {0xc0, 0, 0, 0, 1, 0, 0},
		"long CID":        long,
		"VN without list": {0x80, 0, 0, 0, 0, 0, 0},
		"VN bad list":     {0x80, 0, 0, 0, 0, 0, 0, 1, 2},
	} {
		_, err := ParseQUICLongHeader(b)
		assert.Error(t, err, name)
	}
}
