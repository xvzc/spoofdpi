package netutil

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsIPv6EgressSource(t *testing.T) {
	tcs := []struct {
		ip   string
		want bool
	}{
		{"2001:db8::5", true},
		{"2a00:1450::1", true},
		{"fd12:3456::1", false},
		{"fe80::1", false},
		{"::1", false},
		{"::", false},
		{"192.0.2.5", false},
		{"::ffff:192.0.2.5", false},
	}
	for _, tc := range tcs {
		t.Run(tc.ip, func(t *testing.T) {
			assert.Equal(t, tc.want, isIPv6EgressSource(net.ParseIP(tc.ip)))
		})
	}
}

func TestIPv6Egress(t *testing.T) {
	// Whether the host has IPv6 egress depends on where the test runs;
	// either way, a reported source must be a usable one.
	src, ok := IPv6Egress()
	if !ok {
		assert.Nil(t, src)
		return
	}
	assert.True(t, isIPv6EgressSource(src), "source %s", src)
}
