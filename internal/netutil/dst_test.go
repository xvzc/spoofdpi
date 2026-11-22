package netutil

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDestination_IsValid(t *testing.T) {
	const listenPort = 8080
	listen := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: listenPort}

	tcs := []struct {
		name  string
		addrs []string
		port  int
		want  bool
	}{
		{"ipv4 unspecified on the listen port", []string{"0.0.0.0"}, listenPort, false},
		{"ipv4 unspecified on another port", []string{"0.0.0.0"}, 443, false},
		{"ipv6 unspecified on the listen port", []string{"::"}, listenPort, false},
		{"ipv6 unspecified on another port", []string{"::"}, 443, false},
		{"ipv4-mapped unspecified", []string{"::ffff:0.0.0.0"}, 443, false},
		{"unspecified among others", []string{"192.0.2.1", "::"}, 443, false},
		{"loopback on the listen port", []string{"127.0.0.1"}, listenPort, false},
		{"ipv6 loopback on the listen port", []string{"::1"}, listenPort, false},
		{"loopback on another port", []string{"127.0.0.1"}, 443, true},
		{"public address on the listen port", []string{"192.0.2.1"}, listenPort, true},
		{"public address on another port", []string{"2001:db8::1"}, 443, true},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			d := &Destination{Host: "example.com", Port: tc.port}
			for _, a := range tc.addrs {
				d.Addrs = append(d.Addrs, net.ParseIP(a))
			}

			ok, err := d.IsValid(listen)
			assert.Equal(t, tc.want, ok)
			if tc.want {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}
