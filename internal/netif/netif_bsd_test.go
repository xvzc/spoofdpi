//go:build darwin || freebsd

package netif

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// ioctlArgSize returns the argument size that the ioctl request req
// encodes, IOCPARM_LEN of <sys/ioccom.h>.
func ioctlArgSize(req uint) uintptr {
	return uintptr(req>>16) & 0x1fff
}

// layoutCase compares a size or an offset with its C value.
type layoutCase struct {
	name string
	got  uintptr
	want uintptr
}

func assertLayout(t *testing.T, tcs []layoutCase) {
	t.Helper()
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.got)
		})
	}
}

func TestInterfaceName(t *testing.T) {
	tcs := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "short", input: "utun3"},
		{name: "longest", input: "tun-spoofdpi-15"},
		{name: "empty", input: "", wantErr: true},
		{name: "too long", input: "tun-spoofdpi-016", wantErr: true},
		{name: "NUL", input: "lo\x000", wantErr: true},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got, err := interfaceName(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.input, unix.ByteSliceToString(got[:]))
			assert.Zero(t, got[unix.IFNAMSIZ-1])
		})
	}
}

func TestNetmask4(t *testing.T) {
	tcs := []struct {
		bits int
		want string
	}{
		{bits: 0, want: "0.0.0.0"},
		{bits: 8, want: "255.0.0.0"},
		{bits: 30, want: "255.255.255.252"},
		{bits: 32, want: "255.255.255.255"},
	}

	for _, tc := range tcs {
		t.Run(tc.want, func(t *testing.T) {
			assert.Equal(t, netip.MustParseAddr(tc.want), netmask4(tc.bits))
		})
	}
}

func TestSockaddrInet4(t *testing.T) {
	sa := sockaddrInet4(netip.MustParseAddr("198.51.100.1"))

	assert.Equal(t, unix.RawSockaddrInet4{
		Len:    16,
		Family: unix.AF_INET,
		Addr:   [4]byte{198, 51, 100, 1},
	}, sa)
}

// TestAddrs_RejectInvalidInput checks the input checks that run before
// any ioctl, so they need neither root nor the interface. The error must
// not wrap an errno: one would mean the input reached the kernel.
func TestAddrs_RejectInvalidInput(t *testing.T) {
	v4 := netip.MustParsePrefix("198.51.100.1/30")

	tcs := []struct {
		name string
		call func() error
	}{
		{
			name: "add IPv6 prefix",
			call: func() error {
				return AddAddr4("lo0", netip.MustParsePrefix("2001:db8::1/64"), netip.Addr{})
			},
		},
		{
			name: "add zero prefix",
			call: func() error { return AddAddr4("lo0", netip.Prefix{}, netip.Addr{}) },
		},
		{
			name: "add IPv6 destination",
			call: func() error {
				return AddAddr4("lo0", v4, netip.MustParseAddr("2001:db8::2"))
			},
		},
		{
			name: "add bad name",
			call: func() error { return AddAddr4("", v4, netip.Addr{}) },
		},
		{
			name: "delete IPv6 address",
			call: func() error { return DelAddr4("lo0", netip.MustParseAddr("2001:db8::1")) },
		},
		{
			name: "delete bad name",
			call: func() error { return DelAddr4("", v4.Addr()) },
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			require.Error(t, err)
			var errno unix.Errno
			assert.False(t, errors.As(err, &errno), "kernel error %v", errno)
		})
	}
}
