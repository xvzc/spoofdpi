//go:build darwin || freebsd

package inject

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func TestIPv4Header(t *testing.T) {
	p := Packet{
		Src:      netip.MustParseAddr("192.0.2.1"),
		Dst:      netip.MustParseAddr("203.0.113.9"),
		Proto:    protoTCP,
		HopLimit: 3,
		L4:       make([]byte, 40),
	}
	assert.Equal(t, &ipv4.Header{
		Version:  4,
		Len:      20,
		TotalLen: 60,
		TTL:      3,
		Protocol: 6,
		Src:      net.IP{192, 0, 2, 1},
		Dst:      net.IP{203, 0, 113, 9},
	}, ipv4Header(p))
}

func TestIPv6Control(t *testing.T) {
	p := Packet{
		Src:      netip.MustParseAddr("2001:db8::1"),
		Dst:      netip.MustParseAddr("2001:db8::2"),
		Proto:    protoUDP,
		HopLimit: 5,
	}
	cm := ipv6Control(p)
	assert.Equal(t, 5, cm.HopLimit)
	assert.Equal(t, net.ParseIP("2001:db8::1"), cm.Src)
	assert.Zero(t, cm.IfIndex)

	// Both the hop limit and the source are marshaled.
	b := cm.Marshal()
	var got ipv6.ControlMessage
	require.NoError(t, got.Parse(b))
	assert.Equal(t, 5, got.HopLimit)
	// Parse reads IPV6_PKTINFO's address into Dst, as on receive.
	assert.Equal(t, net.ParseIP("2001:db8::1"), got.Dst)
}

func TestCheckPacket(t *testing.T) {
	v4 := Packet{
		Src:      netip.MustParseAddr("192.0.2.1"),
		Dst:      netip.MustParseAddr("192.0.2.2"),
		Proto:    protoTCP,
		HopLimit: 1,
	}
	v6 := Packet{
		Src:      netip.MustParseAddr("2001:db8::1"),
		Dst:      netip.MustParseAddr("2001:db8::2"),
		Proto:    protoUDP,
		HopLimit: 1,
	}
	assert.NoError(t, checkPacket(v4, netutil.FamilyV4))
	assert.NoError(t, checkPacket(v6, netutil.FamilyV6))
	assert.Error(t, checkPacket(v4, netutil.FamilyV6))
	assert.Error(t, checkPacket(v6, netutil.FamilyV4))

	mixed := v4
	mixed.Dst = v6.Dst
	assert.Error(t, checkPacket(mixed, netutil.FamilyV4))

	mapped := v4
	mapped.Dst = netip.MustParseAddr("::ffff:192.0.2.2")
	assert.Error(t, checkPacket(mapped, netutil.FamilyV4))

	noSrc := v4
	noSrc.Src = netip.Addr{}
	assert.Error(t, checkPacket(noSrc, netutil.FamilyV4))

	icmp := v4
	icmp.Proto = 1
	assert.Error(t, checkPacket(icmp, netutil.FamilyV4))

	zeroHops := v6
	zeroHops.HopLimit = 0
	assert.Error(t, checkPacket(zeroHops, netutil.FamilyV6))
}

func TestOpen_NeedsRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("runs only without root")
	}
	for _, fam := range []netutil.Family{netutil.FamilyV4, netutil.FamilyV6} {
		t.Run(fam.String(), func(t *testing.T) {
			s, err := Open(fam, Options{})
			require.ErrorIs(t, err, ErrNeedsRoot)
			assert.True(t, s == nil, "a nil interface, not a typed nil: %#v", s)
		})
	}
}

func TestOpen_ControlError(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: raw sockets")
	}
	boom := errors.New("boom")
	control := func(string, string, syscall.RawConn) error { return boom }
	for _, fam := range []netutil.Family{netutil.FamilyV4, netutil.FamilyV6} {
		t.Run(fam.String(), func(t *testing.T) {
			_, err := Open(fam, Options{Control: control})
			require.ErrorIs(t, err, boom)
			assert.NotErrorIs(t, err, ErrNeedsRoot)
		})
	}
}

func TestOpen_UnknownFamily(t *testing.T) {
	_, err := Open(0, Options{})
	assert.Error(t, err)
}
