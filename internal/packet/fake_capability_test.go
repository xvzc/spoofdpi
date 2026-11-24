package packet

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xvzc/spoofdpi/internal/netutil"
)

func TestFakesOffError_Error(t *testing.T) {
	err := &FakesOffError{Family: netutil.FamilyV6, Reason: "not supported yet"}
	assert.Equal(t, "fake packets are off for ipv6: not supported yet", err.Error())
}

func TestStaticGate_CanFake(t *testing.T) {
	off4 := &FakesOffError{Family: netutil.FamilyV4, Reason: "v4 off"}
	off6 := &FakesOffError{Family: netutil.FamilyV6, Reason: "v6 off"}

	tcs := []struct {
		name   string
		v4, v6 error
		ip     net.IP
		want   error
	}{
		{"ipv4 allowed", nil, off6, net.ParseIP("203.0.113.1"), nil},
		{"ipv4-mapped is ipv4", nil, off6, net.ParseIP("::ffff:203.0.113.1"), nil},
		{"ipv6 off", nil, off6, net.ParseIP("2001:db8::1"), off6},
		{"link-local ipv6 off", nil, off6, net.ParseIP("fe80::1"), off6},
		{"ipv4 off", off4, nil, net.ParseIP("203.0.113.1"), off4},
		{"ipv6 allowed", off4, nil, net.ParseIP("2001:db8::1"), nil},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, NewStaticGate(tc.v4, tc.v6).CanFake(tc.ip))
		})
	}

	t.Run("nil dst", func(t *testing.T) {
		assert.Error(t, NewStaticGate(nil, nil).CanFake(nil))
	})
	t.Run("invalid dst", func(t *testing.T) {
		assert.Error(t, NewStaticGate(nil, nil).CanFake(net.IP{1, 2, 3}))
	})
}
