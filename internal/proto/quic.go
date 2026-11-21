package proto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	QUICVersion1 uint32 = 0x00000001
	// QUICMinInitialSize is the smallest datagram a client Initial may be
	// sent in (RFC 9000, section 14.1).
	QUICMinInitialSize = 1200
	// QUICMaxCIDLen is the longest connection ID of QUIC v1 (RFC 9000,
	// section 17.2).
	QUICMaxCIDLen = 20
)

// Transport parameter IDs (RFC 9000, section 18.2).
const (
	QUICTPMaxIdleTimeout                 = 0x01
	QUICTPMaxUDPPayloadSize              = 0x03
	QUICTPInitialMaxData                 = 0x04
	QUICTPInitialMaxStreamDataBidiLocal  = 0x05
	QUICTPInitialMaxStreamDataBidiRemote = 0x06
	QUICTPInitialMaxStreamDataUni        = 0x07
	QUICTPInitialMaxStreamsBidi          = 0x08
	QUICTPInitialMaxStreamsUni           = 0x09
	QUICTPInitialSourceConnectionID      = 0x0f
)

// quicV1InitialSalt is the salt the Initial secrets of QUIC v1 are
// extracted with (RFC 9001, section 5.2).
var quicV1InitialSalt = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
	0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
}

// QUICPacketType is the type of a QUIC long-header packet.
type QUICPacketType uint8

const (
	// QUICInitial to QUICRetry are the v1 long-header type bits 0b00 to
	// 0b11.
	QUICInitial QUICPacketType = iota
	QUIC0RTT
	QUICHandshake
	QUICRetry
	// QUICVersionNegotiation is a packet whose version field is 0; it has
	// no type bits.
	QUICVersionNegotiation
)

const (
	quicLongHeaderBit = 0x80
	quicFixedBit      = 0x40
	quicTagLen        = 16
	quicSampleLen     = 16
	// quicLengthLen is the size of the Length field SealQUICInitial
	// writes: always a 2-byte varint.
	quicLengthLen = 2
	quicMaxLength = 1<<14 - 1
)

// QUICInitialKeys are the AES-128-GCM keys of one direction of the
// Initial packet number space.
type QUICInitialKeys struct {
	Key, IV, HP []byte
}

// QUICInitialKeysFor derives the QUIC v1 Initial keys of the client, or of
// the server when server is set, from the Destination Connection ID of the
// client's first Initial (RFC 9001, section 5.2).
func QUICInitialKeysFor(dcid []byte, server bool) (QUICInitialKeys, error) {
	initial, err := hkdf.Extract(sha256.New, dcid, quicV1InitialSalt)
	if err != nil {
		return QUICInitialKeys{}, err
	}
	label := "client in"
	if server {
		label = "server in"
	}
	secret, err := hkdfExpandLabel(initial, label, sha256.Size)
	if err != nil {
		return QUICInitialKeys{}, err
	}
	var keys QUICInitialKeys
	if keys.Key, err = hkdfExpandLabel(secret, "quic key", 16); err != nil {
		return QUICInitialKeys{}, err
	}
	if keys.IV, err = hkdfExpandLabel(secret, "quic iv", 12); err != nil {
		return QUICInitialKeys{}, err
	}
	if keys.HP, err = hkdfExpandLabel(secret, "quic hp", 16); err != nil {
		return QUICInitialKeys{}, err
	}
	return keys, nil
}

// hkdfExpandLabel is the HKDF-Expand-Label of TLS 1.3 (RFC 8446, section
// 7.1) with SHA-256 and an empty context.
func hkdfExpandLabel(secret []byte, label string, n int) ([]byte, error) {
	full := "tls13 " + label
	info := make([]byte, 0, 4+len(full))
	info = binary.BigEndian.AppendUint16(info, uint16(n))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0)
	return hkdf.Expand(sha256.New, secret, string(info), n)
}

// QUICInitialPacket is the content of a QUIC v1 Initial packet.
type QUICInitialPacket struct {
	DCID, SCID, Token []byte
	// PacketNumber is the full packet number; it is encoded in its PNLen
	// low bytes.
	PacketNumber uint64
	// PNLen is the length of the encoded packet number, 1 to 4.
	PNLen int
	// Payload is the plaintext frames.
	Payload []byte
}

// SealQUICInitial returns p as a protected QUIC v1 Initial packet (RFC
// 9001, section 5), sealed with keys. Its Length field is always a 2-byte
// varint. If padTo is positive, PADDING frames are added to the payload so
// that the packet is padTo bytes, unless it is already longer. The payload
// is always padded enough for the header protection sample.
func SealQUICInitial(
	p QUICInitialPacket,
	keys QUICInitialKeys,
	padTo int,
) ([]byte, error) {
	if p.PNLen < 1 || p.PNLen > 4 {
		return nil, fmt.Errorf("packet number length %d is not 1 to 4", p.PNLen)
	}
	if len(p.DCID) > QUICMaxCIDLen || len(p.SCID) > QUICMaxCIDLen {
		return nil, errors.New("connection ID longer than 20 bytes")
	}

	hdr := []byte{
		quicLongHeaderBit | quicFixedBit | byte(QUICInitial)<<4 | byte(p.PNLen-1),
	}
	hdr = binary.BigEndian.AppendUint32(hdr, QUICVersion1)
	hdr = append(hdr, byte(len(p.DCID)))
	hdr = append(hdr, p.DCID...)
	hdr = append(hdr, byte(len(p.SCID)))
	hdr = append(hdr, p.SCID...)
	hdr = AppendQUICVarint(hdr, uint64(len(p.Token)))
	hdr = append(hdr, p.Token...)
	pnOffset := len(hdr) + quicLengthLen

	payloadLen := len(p.Payload)
	if padTo > 0 {
		payloadLen = max(payloadLen, padTo-pnOffset-p.PNLen-quicTagLen)
	}
	// The sample starts 4 bytes after the packet number begins.
	payloadLen = max(payloadLen, 4+quicSampleLen-p.PNLen-quicTagLen)
	length := p.PNLen + payloadLen + quicTagLen
	if length > quicMaxLength {
		return nil, fmt.Errorf("packet length %d does not fit 2 bytes", length)
	}
	hdr = binary.BigEndian.AppendUint16(hdr, 0x4000|uint16(length))
	for i := p.PNLen - 1; i >= 0; i-- {
		hdr = append(hdr, byte(p.PacketNumber>>(8*i)))
	}

	block, err := aes.NewCipher(keys.Key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(keys.IV) != aead.NonceSize() {
		return nil, fmt.Errorf("IV is %d bytes, not %d", len(keys.IV), aead.NonceSize())
	}
	nonce := make([]byte, len(keys.IV))
	copy(nonce, keys.IV)
	for i := range 8 {
		nonce[len(nonce)-1-i] ^= byte(p.PacketNumber >> (8 * i))
	}
	plain := make([]byte, payloadLen)
	copy(plain, p.Payload)
	pkt := aead.Seal(hdr, nonce, plain, hdr)

	hp, err := aes.NewCipher(keys.HP)
	if err != nil {
		return nil, err
	}
	mask := make([]byte, aes.BlockSize)
	sample := pnOffset + 4
	hp.Encrypt(mask, pkt[sample:sample+quicSampleLen])
	pkt[0] ^= mask[0] & 0x0f
	for i := range p.PNLen {
		pkt[pnOffset+i] ^= mask[1+i]
	}
	return pkt, nil
}

// QUICLongHeader is the version-independent long header (RFC 8999) of the
// first packet in a datagram.
type QUICLongHeader struct {
	// Type is set for QUIC v1 packets and Version Negotiation.
	Type       QUICPacketType
	Version    uint32
	DCID, SCID []byte
	// SupportedVersions are the versions of a Version Negotiation packet.
	SupportedVersions []uint32
}

// ParseQUICLongHeader parses the long header at the start of b. It does
// not remove the header protection, nor decrypt. It fails on a short
// header, a truncated packet, and, for v1, a connection ID longer than 20
// bytes. The type of a version other than v1 is not known, and is left
// QUICInitial.
func ParseQUICLongHeader(b []byte) (QUICLongHeader, error) {
	if len(b) < 7 {
		return QUICLongHeader{}, errors.New("QUIC packet too short")
	}
	if b[0]&quicLongHeaderBit == 0 {
		return QUICLongHeader{}, errors.New("not a QUIC long header")
	}
	h := QUICLongHeader{Version: binary.BigEndian.Uint32(b[1:5])}
	rest := b[5:]
	cid := func() ([]byte, error) {
		if len(rest) < 1 || len(rest) < 1+int(rest[0]) {
			return nil, errors.New("QUIC connection ID truncated")
		}
		id := rest[1 : 1+int(rest[0])]
		rest = rest[1+int(rest[0]):]
		return id, nil
	}
	var err error
	if h.DCID, err = cid(); err != nil {
		return QUICLongHeader{}, err
	}
	if h.SCID, err = cid(); err != nil {
		return QUICLongHeader{}, err
	}

	switch h.Version {
	case 0:
		h.Type = QUICVersionNegotiation
		if len(rest) == 0 || len(rest)%4 != 0 {
			return QUICLongHeader{}, errors.New("QUIC version list malformed")
		}
		for ; len(rest) > 0; rest = rest[4:] {
			h.SupportedVersions = append(
				h.SupportedVersions,
				binary.BigEndian.Uint32(rest),
			)
		}
	case QUICVersion1:
		if len(h.DCID) > QUICMaxCIDLen || len(h.SCID) > QUICMaxCIDLen {
			return QUICLongHeader{}, errors.New("QUIC connection ID longer than 20 bytes")
		}
		h.Type = QUICPacketType(b[0] >> 4 & 0x03)
		if h.Type != QUICRetry && len(rest) == 0 {
			return QUICLongHeader{}, errors.New("QUIC packet truncated")
		}
	}
	return h, nil
}

// AppendQUICVarint appends v as a QUIC variable-length integer (RFC 9000,
// section 16) in its shortest encoding. It panics if v is 2^62 or more.
func AppendQUICVarint(b []byte, v uint64) []byte {
	switch {
	case v < 1<<6:
		return append(b, byte(v))
	case v < 1<<14:
		return binary.BigEndian.AppendUint16(b, 0x4000|uint16(v))
	case v < 1<<30:
		return binary.BigEndian.AppendUint32(b, 0x80000000|uint32(v))
	case v < 1<<62:
		return binary.BigEndian.AppendUint64(b, 0xc000000000000000|v)
	}
	panic(fmt.Sprintf("QUIC varint %d out of range", v))
}

// ReadQUICVarint reads the variable-length integer at the start of b and
// returns it with its length.
func ReadQUICVarint(b []byte) (v uint64, n int, err error) {
	if len(b) == 0 {
		return 0, 0, errors.New("QUIC varint truncated")
	}
	n = 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0, errors.New("QUIC varint truncated")
	}
	v = uint64(b[0] & 0x3f)
	for _, c := range b[1:n] {
		v = v<<8 | uint64(c)
	}
	return v, n, nil
}

// AppendQUICCryptoFrame appends a CRYPTO frame carrying data at offset.
func AppendQUICCryptoFrame(b []byte, offset uint64, data []byte) []byte {
	b = append(b, 0x06)
	b = AppendQUICVarint(b, offset)
	b = AppendQUICVarint(b, uint64(len(data)))
	return append(b, data...)
}

// AppendQUICTransportParameter appends the transport parameter id with
// value.
func AppendQUICTransportParameter(b []byte, id uint64, value []byte) []byte {
	b = AppendQUICVarint(b, id)
	b = AppendQUICVarint(b, uint64(len(value)))
	return append(b, value...)
}
