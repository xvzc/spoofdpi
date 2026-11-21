package probe

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
)

const (
	// quicRequestSize is the size of the probe datagram: servers drop
	// smaller packets of an unsupported version (RFC 9000, section 5.2.2).
	quicRequestSize = 1200
	quicCIDLen      = 8
)

// newQUICRequest returns a QUIC long-header packet of a reserved version,
// which a server answers with a Version Negotiation packet (RFC 9000,
// sections 6 and 15), and its random destination and source connection
// IDs.
func newQUICRequest() (req, dcid, scid []byte) {
	req = make([]byte, quicRequestSize)
	req[0] = 0xC0 // long header, fixed bit, type Initial
	var v [4]byte
	_, _ = rand.Read(v[:])
	// Versions of the form 0x?a?a?a?a are reserved to force version
	// negotiation.
	version := binary.BigEndian.Uint32(v[:])&0xF0F0F0F0 | 0x0A0A0A0A
	binary.BigEndian.PutUint32(req[1:5], version)

	req[5] = quicCIDLen
	dcid = req[6 : 6+quicCIDLen]
	_, _ = rand.Read(dcid)
	req[6+quicCIDLen] = quicCIDLen
	scid = req[7+quicCIDLen : 7+2*quicCIDLen]
	_, _ = rand.Read(scid)
	// The rest is zero padding.
	return req, bytes.Clone(dcid), bytes.Clone(scid)
}

// isVersionNegotiation reports whether b is a Version Negotiation packet
// that answers a request with the connection IDs dcid and scid: it echoes
// scid as its destination and dcid as its source (RFC 9000, section
// 17.2.1).
func isVersionNegotiation(b, dcid, scid []byte) bool {
	if len(b) < 7 || b[0]&0x80 == 0 || binary.BigEndian.Uint32(b[1:5]) != 0 {
		return false
	}
	rest := b[5:]
	cid := func() ([]byte, bool) {
		if len(rest) < 1 || len(rest) < 1+int(rest[0]) {
			return nil, false
		}
		id := rest[1 : 1+int(rest[0])]
		rest = rest[1+int(rest[0]):]
		return id, true
	}
	gotDCID, ok := cid()
	if !ok || !bytes.Equal(gotDCID, scid) {
		return false
	}
	gotSCID, ok := cid()
	if !ok || !bytes.Equal(gotSCID, dcid) {
		return false
	}
	return len(rest) > 0 && len(rest)%4 == 0
}
