package proto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseTLSAlert(t *testing.T) {
	tcs := []struct {
		name   string
		input  []byte
		wantOK bool
		want   TLSAlertMessage
	}{
		{
			name:   "alert record",
			input:  []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x32},
			wantOK: true,
			want:   TLSAlertMessage{Level: 2, Description: TLSAlertDescDecodeError},
		},
		{
			name:   "alert record followed by more bytes",
			input:  []byte{0x15, 0x03, 0x01, 0x00, 0x02, 0x01, 0x00, 0xde, 0xad},
			wantOK: true,
			want:   TLSAlertMessage{Level: 1, Description: 0},
		},
		{
			name:  "handshake record",
			input: []byte{0x16, 0x03, 0x03, 0x00, 0x02, 0x02, 0x32},
		},
		{
			name:  "short read",
			input: []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02},
		},
		{
			name:  "header only",
			input: []byte{0x15, 0x03, 0x03, 0x00, 0x02},
		},
		{
			name:  "alert record whose body is not two bytes",
			input: []byte{0x15, 0x03, 0x03, 0x00, 0x20, 0x02, 0x32},
		},
		{
			name:  "alert type without a tls version",
			input: []byte{0x15, 0x00, 0x00, 0x00, 0x02, 0x02, 0x32},
		},
		{
			name:  "non-tls reply",
			input: []byte("HTTP/1.1 400 Bad Request\r\n"),
		},
		{name: "empty", input: nil},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ParseTLSAlert(tc.input)
			assert.Equal(t, tc.wantOK, ok)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestTLSAlertMessage_Name(t *testing.T) {
	tcs := []struct {
		description byte
		want        string
	}{
		{0, "close_notify"},
		{10, "unexpected_message"},
		{20, "bad_record_mac"},
		{22, "record_overflow"},
		{30, "decompression_failure"},
		{40, "handshake_failure"},
		{42, "bad_certificate"},
		{43, "unsupported_certificate"},
		{44, "certificate_revoked"},
		{45, "certificate_expired"},
		{46, "certificate_unknown"},
		{47, "illegal_parameter"},
		{48, "unknown_ca"},
		{49, "access_denied"},
		{50, "decode_error"},
		{51, "decrypt_error"},
		{70, "protocol_version"},
		{71, "insufficient_security"},
		{80, "internal_error"},
		{86, "inappropriate_fallback"},
		{90, "user_canceled"},
		{100, "no_renegotiation"},
		{109, "missing_extension"},
		{110, "unsupported_extension"},
		{112, "unrecognized_name"},
		{113, "bad_certificate_status_response"},
		{115, "unknown_psk_identity"},
		{116, "certificate_required"},
		{120, "no_application_protocol"},
		{118, "118"},
		{255, "255"},
	}

	for _, tc := range tcs {
		assert.Equal(t, tc.want, TLSAlertMessage{Description: tc.description}.Name())
	}
}

func TestTLSAlertMessage_RejectsClientHello(t *testing.T) {
	for d := range 256 {
		want := d == 10 || d == 47 || d == 50
		assert.Equal(t, want, TLSAlertMessage{Description: byte(d)}.RejectsClientHello(), d)
	}
}
