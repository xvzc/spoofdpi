package proto

import (
	"bytes"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSOCKS5Reply_Write(t *testing.T) {
	tcs := []struct {
		name string
		ip   net.IP
		want []byte
	}{
		{
			"ipv4",
			net.IPv4(192, 0, 2, 5),
			[]byte{5, 0, 0, 1, 192, 0, 2, 5, 0x1f, 0x90},
		},
		{
			"ipv4-mapped ipv6",
			net.ParseIP("::ffff:192.0.2.5"),
			[]byte{5, 0, 0, 1, 192, 0, 2, 5, 0x1f, 0x90},
		},
		{
			"ipv6 loopback",
			net.IPv6loopback,
			[]byte{5, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x1f, 0x90},
		},
		{
			"ipv6",
			net.ParseIP("2001:db8::5"),
			[]byte{
				5, 0, 0, 4,
				0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5,
				0x1f, 0x90,
			},
		},
		{
			"nil",
			nil,
			[]byte{5, 0, 0, 1, 0, 0, 0, 0, 0x1f, 0x90},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			r := SOCKS5SuccessResponse().Port(8080)
			// Bind ignores nil, so set the field directly to cover it.
			r.BindIP = tc.ip

			var buf bytes.Buffer
			require.NoError(t, r.Write(&buf))
			assert.Equal(t, tc.want, buf.Bytes())
		})
	}
}

func TestSOCKS5Reply_Write_Defaults(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, SOCKS5FailureResponse().Write(&buf))
	assert.Equal(t, []byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0}, buf.Bytes())
}
