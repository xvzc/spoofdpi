package probe

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"

	"github.com/xvzc/spoofdpi/internal/proto"
)

// quicTransportParameters returns the transport parameters of the QUIC
// ClientHello, with scid as the initial_source_connection_id that RFC 9000,
// section 7.3, requires. The others are those of a usual client.
func quicTransportParameters(scid []byte) []byte {
	integer := func(b []byte, id, v uint64) []byte {
		return proto.AppendQUICTransportParameter(b, id, proto.AppendQUICVarint(nil, v))
	}
	var b []byte
	b = proto.AppendQUICTransportParameter(b, proto.QUICTPInitialSourceConnectionID, scid)
	b = integer(b, proto.QUICTPMaxIdleTimeout, 30000)
	b = integer(b, proto.QUICTPMaxUDPPayloadSize, 1472)
	b = integer(b, proto.QUICTPInitialMaxData, 1<<20)
	b = integer(b, proto.QUICTPInitialMaxStreamDataBidiLocal, 1<<18)
	b = integer(b, proto.QUICTPInitialMaxStreamDataBidiRemote, 1<<18)
	b = integer(b, proto.QUICTPInitialMaxStreamDataUni, 1<<18)
	b = integer(b, proto.QUICTPInitialMaxStreamsBidi, 100)
	b = integer(b, proto.QUICTPInitialMaxStreamsUni, 100)
	return b
}

// buildQUICClientHello returns the ClientHello Go's QUIC client sends to
// host, as the CRYPTO data of its first Initial, whose transport
// parameters name scid. An IP literal host gets no SNI. The key exchange
// is pinned to X25519, so that the ClientHello fits one Initial packet.
func buildQUICClientHello(host string, scid []byte) ([]byte, error) {
	q := tls.QUICClient(&tls.QUICConfig{TLSConfig: &tls.Config{
		ServerName:       host,
		NextProtos:       []string{"h3"},
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519},
	}})
	defer func() { _ = q.Close() }()
	q.SetTransportParameters(quicTransportParameters(scid))
	if err := q.Start(context.Background()); err != nil {
		return nil, fmt.Errorf("build QUIC ClientHello: %w", err)
	}
	var hello []byte
	for {
		e := q.NextEvent()
		switch e.Kind {
		case tls.QUICNoEvent:
			if len(hello) == 0 {
				return nil, errors.New("build QUIC ClientHello: no ClientHello written")
			}
			return hello, nil
		case tls.QUICWriteData:
			if e.Level == tls.QUICEncryptionLevelInitial {
				// e.Data is reused by the next NextEvent.
				hello = append(hello, e.Data...)
			}
		}
	}
}

// quicInitialCIDLen is the length of the connection IDs of the Initial.
const quicInitialCIDLen = 8

// newQUICInitial returns a client Initial of proto.QUICMinInitialSize
// bytes, with fresh random connection IDs dcid and scid and packet number
// 0, that carries the ClientHello for host in one CRYPTO frame.
func newQUICInitial(host string) (pkt, dcid, scid []byte, err error) {
	dcid = make([]byte, quicInitialCIDLen)
	scid = make([]byte, quicInitialCIDLen)
	_, _ = rand.Read(dcid)
	_, _ = rand.Read(scid)

	hello, err := buildQUICClientHello(host, scid)
	if err != nil {
		return nil, nil, nil, err
	}
	keys, err := proto.QUICInitialKeysFor(dcid, false)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("QUIC Initial keys: %w", err)
	}
	pkt, err = proto.SealQUICInitial(proto.QUICInitialPacket{
		DCID:    dcid,
		SCID:    scid,
		PNLen:   2,
		Payload: proto.AppendQUICCryptoFrame(nil, 0, hello),
	}, keys, proto.QUICMinInitialSize)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("seal QUIC Initial: %w", err)
	}
	// A ClientHello that does not fit would need a second Initial, which
	// the QUIC check does not send.
	if len(pkt) > proto.QUICMinInitialSize {
		return nil, nil, nil, fmt.Errorf(
			"QUIC ClientHello of %d bytes does not fit one Initial", len(hello))
	}
	return pkt, dcid, scid, nil
}
