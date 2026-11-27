package netif

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

// The C values come from <net/if.h> and <netinet/in_var.h> of FreeBSD
// 15.0, the same on amd64 and arm64: struct ifreq is 32 bytes with
// ifr_flags and ifr_flagshigh, struct in_aliasreq ends in an int
// ifra_vhid, and struct ifstat holds IFSTATMAX + 1 = 801 characters.
//
// The same checks as constant expressions make a wrong layout fail to
// compile, so cross-compiling the tests with go vet checks every GOARCH.
var (
	_ [32]byte  = [unsafe.Sizeof(ifreqFlags{})]byte{}
	_ [32]byte  = [unsafe.Sizeof(ifreqAddr{})]byte{}
	_ [32]byte  = [unsafe.Sizeof(ifreqName{})]byte{}
	_ [68]byte  = [unsafe.Sizeof(inAliasreq{})]byte{}
	_ [817]byte = [unsafe.Sizeof(ifstat{})]byte{}
	_ [18]byte  = [unsafe.Offsetof(ifreqFlags{}.FlagsHigh)]byte{}
	_ [64]byte  = [unsafe.Offsetof(inAliasreq{}.Vhid)]byte{}
)

func TestLayout(t *testing.T) {
	assertLayout(t, []layoutCase{
		{"ifreqFlags size", unsafe.Sizeof(ifreqFlags{}), 32},
		{"ifreqFlags.Flags offset", unsafe.Offsetof(ifreqFlags{}.Flags), 16},
		{"ifreqFlags.FlagsHigh offset", unsafe.Offsetof(ifreqFlags{}.FlagsHigh), 18},
		{"ifreqAddr size", unsafe.Sizeof(ifreqAddr{}), 32},
		{"ifreqAddr.Addr offset", unsafe.Offsetof(ifreqAddr{}.Addr), 16},
		{"ifreqName size", unsafe.Sizeof(ifreqName{}), 32},
		{"inAliasreq size", unsafe.Sizeof(inAliasreq{}), 68},
		{"inAliasreq.Addr offset", unsafe.Offsetof(inAliasreq{}.Addr), 16},
		{"inAliasreq.Dstaddr offset", unsafe.Offsetof(inAliasreq{}.Dstaddr), 32},
		{"inAliasreq.Mask offset", unsafe.Offsetof(inAliasreq{}.Mask), 48},
		{"inAliasreq.Vhid offset", unsafe.Offsetof(inAliasreq{}.Vhid), 64},
		{"ifstat size", unsafe.Sizeof(ifstat{}), 817},
		{"SIOCAIFADDR", ioctlArgSize(siocAIFADDR), unsafe.Sizeof(inAliasreq{})},
		{"SIOCDIFADDR", ioctlArgSize(unix.SIOCDIFADDR), unsafe.Sizeof(ifreqAddr{})},
		{"SIOCGIFFLAGS", ioctlArgSize(unix.SIOCGIFFLAGS), unsafe.Sizeof(ifreqFlags{})},
		{"SIOCSIFFLAGS", ioctlArgSize(unix.SIOCSIFFLAGS), unsafe.Sizeof(ifreqFlags{})},
		{"SIOCIFDESTROY", ioctlArgSize(unix.SIOCIFDESTROY), unsafe.Sizeof(ifreqName{})},
		{"SIOCGIFSTATUS", ioctlArgSize(unix.SIOCGIFSTATUS), unsafe.Sizeof(ifstat{})},
	})
}

// TestSIOCAIFADDR checks the command against _IOW('i', 43, struct
// in_aliasreq) of <sys/sockio.h>.
func TestSIOCAIFADDR(t *testing.T) {
	const iocIn = 0x80000000
	want := uint(iocIn | unsafe.Sizeof(inAliasreq{})<<16 | 'i'<<8 | 43)

	assert.Equal(t, want, uint(siocAIFADDR))
}

func TestIfreqFlags(t *testing.T) {
	var r ifreqFlags

	assert.NoError(t, r.setFlags(0x00218843))
	assert.Equal(t, uint16(0x8843), r.Flags)
	assert.Equal(t, uint16(0x0021), r.FlagsHigh)
	assert.Equal(t, uint32(0x00218843), r.flags())
}
