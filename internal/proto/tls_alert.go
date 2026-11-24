package proto

import "strconv"

// TLS alert descriptions that mean the server could not parse the Client
// Hello, which is what it answers a fake Client Hello with.
const (
	TLSAlertDescUnexpectedMessage byte = 10
	TLSAlertDescIllegalParameter  byte = 47
	TLSAlertDescDecodeError       byte = 50
)

// tlsAlertRecordLen is the length of a TLS alert record: the header, then
// the level and the description.
const tlsAlertRecordLen = TLSHeaderLen + 2

// tlsAlertNames are the alert names of RFC 8446 and RFC 5246.
var tlsAlertNames = map[byte]string{
	0:   "close_notify",
	10:  "unexpected_message",
	20:  "bad_record_mac",
	22:  "record_overflow",
	30:  "decompression_failure",
	40:  "handshake_failure",
	42:  "bad_certificate",
	43:  "unsupported_certificate",
	44:  "certificate_revoked",
	45:  "certificate_expired",
	46:  "certificate_unknown",
	47:  "illegal_parameter",
	48:  "unknown_ca",
	49:  "access_denied",
	50:  "decode_error",
	51:  "decrypt_error",
	70:  "protocol_version",
	71:  "insufficient_security",
	80:  "internal_error",
	86:  "inappropriate_fallback",
	90:  "user_canceled",
	100: "no_renegotiation",
	109: "missing_extension",
	110: "unsupported_extension",
	112: "unrecognized_name",
	113: "bad_certificate_status_response",
	115: "unknown_psk_identity",
	116: "certificate_required",
	120: "no_application_protocol",
}

// TLSAlertMessage is the level and the description of a TLS alert.
type TLSAlertMessage struct {
	Level       byte
	Description byte
}

// Name returns the RFC name of the alert description, or its number when
// it has no name.
func (a TLSAlertMessage) Name() string {
	if name, ok := tlsAlertNames[a.Description]; ok {
		return name
	}
	return strconv.Itoa(int(a.Description))
}

// RejectsClientHello reports whether the description is one that a server
// gives to a Client Hello it can't parse or make sense of.
func (a TLSAlertMessage) RejectsClientHello() bool {
	switch a.Description {
	case TLSAlertDescUnexpectedMessage,
		TLSAlertDescIllegalParameter,
		TLSAlertDescDecodeError:
		return true
	default:
		return false
	}
}

// ParseTLSAlert returns the alert that b starts with, and reports whether b
// starts with one: a whole plaintext alert record, 7 bytes. Anything after
// the record is ignored.
func ParseTLSAlert(b []byte) (TLSAlertMessage, bool) {
	if len(b) < tlsAlertRecordLen ||
		TLSMessageType(b[0]) != TLSAlert ||
		b[1] != 0x03 ||
		b[3] != 0 || b[4] != 2 {
		return TLSAlertMessage{}, false
	}
	return TLSAlertMessage{Level: b[5], Description: b[6]}, true
}
