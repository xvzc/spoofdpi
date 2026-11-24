//go:build darwin || freebsd

package inject

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIPv4Control_None(t *testing.T) {
	p := Packet{
		Src:      netip.MustParseAddr("192.0.2.1"),
		Dst:      netip.MustParseAddr("203.0.113.9"),
		Proto:    protoTCP,
		HopLimit: 3,
	}
	assert.Nil(t, ipv4Control(p))
}
