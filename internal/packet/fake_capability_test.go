package packet

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStacks_CanFake(t *testing.T) {
	caps := map[string]FakeCapability{"tcp": &TCPStack{}, "udp": &UDPStack{}}
	tcs := []struct {
		ip   string
		want bool
	}{
		{"203.0.113.1", true},
		{"::ffff:203.0.113.1", true},
		{"2001:db8::1", false},
		{"fe80::1", false},
	}

	for name, c := range caps {
		for _, tc := range tcs {
			assert.Equal(t, tc.want, c.CanFake(net.ParseIP(tc.ip)), "%s %s", name, tc.ip)
		}
	}
}
