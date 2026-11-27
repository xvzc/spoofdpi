package netif

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

// The C values come from <net/if.h> and <netinet/in_var.h> of the macOS
// SDK, the same on amd64 and arm64: struct ifreq is 32 bytes with a short
// ifr_flags, and struct in_aliasreq has no ifra_vhid.
//
// The same checks as constant expressions make a wrong layout fail to
// compile, so cross-compiling the tests with go vet checks every GOARCH.
var (
	_ [32]byte = [unsafe.Sizeof(ifreqFlags{})]byte{}
	_ [32]byte = [unsafe.Sizeof(ifreqAddr{})]byte{}
	_ [64]byte = [unsafe.Sizeof(inAliasreq{})]byte{}
	_ [16]byte = [unsafe.Offsetof(ifreqFlags{}.Flags)]byte{}
	_ [48]byte = [unsafe.Offsetof(inAliasreq{}.Mask)]byte{}
)

func TestLayout(t *testing.T) {
	assertLayout(t, []layoutCase{
		{"ifreqFlags size", unsafe.Sizeof(ifreqFlags{}), 32},
		{"ifreqFlags.Flags offset", unsafe.Offsetof(ifreqFlags{}.Flags), 16},
		{"ifreqAddr size", unsafe.Sizeof(ifreqAddr{}), 32},
		{"ifreqAddr.Addr offset", unsafe.Offsetof(ifreqAddr{}.Addr), 16},
		{"inAliasreq size", unsafe.Sizeof(inAliasreq{}), 64},
		{"inAliasreq.Addr offset", unsafe.Offsetof(inAliasreq{}.Addr), 16},
		{"inAliasreq.Dstaddr offset", unsafe.Offsetof(inAliasreq{}.Dstaddr), 32},
		{"inAliasreq.Mask offset", unsafe.Offsetof(inAliasreq{}.Mask), 48},
		{"SIOCAIFADDR", ioctlArgSize(siocAIFADDR), unsafe.Sizeof(inAliasreq{})},
		{"SIOCDIFADDR", ioctlArgSize(unix.SIOCDIFADDR), unsafe.Sizeof(ifreqAddr{})},
		{"SIOCGIFFLAGS", ioctlArgSize(unix.SIOCGIFFLAGS), unsafe.Sizeof(ifreqFlags{})},
		{"SIOCSIFFLAGS", ioctlArgSize(unix.SIOCSIFFLAGS), unsafe.Sizeof(ifreqFlags{})},
	})
}

func TestIfreqFlags(t *testing.T) {
	var r ifreqFlags

	assert.NoError(t, r.setFlags(0x8863))
	assert.Equal(t, uint16(0x8863), r.Flags)
	assert.Equal(t, uint32(0x8863), r.flags())
	assert.Error(t, r.setFlags(0x10000))
}
