package server

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPACProxyHostPort(t *testing.T) {
	tcs := []struct {
		ip   net.IP
		want string
	}{
		{nil, "127.0.0.1:8080"},
		{net.IPv4zero, "127.0.0.1:8080"},
		{net.IPv6unspecified, "127.0.0.1:8080"},
		{net.IPv4(127, 0, 0, 1), "127.0.0.1:8080"},
		{net.IPv6loopback, "[::1]:8080"},
		{net.ParseIP("192.0.2.5"), "192.0.2.5:8080"},
		{net.ParseIP("2001:db8::5"), "[2001:db8::5]:8080"},
	}
	for _, tc := range tcs {
		t.Run(tc.ip.String(), func(t *testing.T) {
			assert.Equal(t, tc.want, PACProxyHostPort(net.TCPAddr{IP: tc.ip, Port: 8080}))
		})
	}
}
