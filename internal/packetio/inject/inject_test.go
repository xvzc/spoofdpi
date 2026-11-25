package inject

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewSendError_Kind(t *testing.T) {
	tcs := []struct {
		name string
		err  error
		want Kind
	}{
		{name: "EPERM", err: syscall.EPERM, want: KindBlocked},
		{name: "EACCES", err: syscall.EACCES, want: KindBlocked},
		{name: "EHOSTUNREACH", err: syscall.EHOSTUNREACH, want: KindUnreachable},
		{name: "ENETUNREACH", err: syscall.ENETUNREACH, want: KindUnreachable},
		{name: "EMSGSIZE", err: syscall.EMSGSIZE, want: KindTooBig},
		{name: "ENOBUFS", err: syscall.ENOBUFS, want: KindNoBuffer},
		{name: "other errno", err: syscall.EINVAL, want: KindOther},
		{name: "not an errno", err: errors.New("boom"), want: KindOther},
		{
			name: "errno wrapped in a syscall error",
			err:  os.NewSyscallError("sendto", syscall.EPERM),
			want: KindBlocked,
		},
		{
			name: "errno wrapped with fmt",
			err:  fmt.Errorf("write: %w", syscall.EMSGSIZE),
			want: KindTooBig,
		},
	}

	dst := netip.MustParseAddr("192.0.2.1")
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got := NewSendError(dst, tc.err)
			assert.Equal(t, tc.want, got.Kind)
			assert.Equal(t, dst, got.Dst)
			assert.ErrorIs(t, got, tc.err)
		})
	}
}

func TestSendError_Error(t *testing.T) {
	err := NewSendError(netip.MustParseAddr("192.0.2.1"), syscall.EPERM)
	assert.Equal(
		t,
		"send to 192.0.2.1 (blocked): "+syscall.EPERM.Error(),
		err.Error(),
	)

	var se *SendError
	assert.ErrorAs(t, fmt.Errorf("fake: %w", err), &se)
}

func TestKind_String(t *testing.T) {
	assert.Equal(t, "other", KindOther.String())
	assert.Equal(t, "blocked", KindBlocked.String())
	assert.Equal(t, "unreachable", KindUnreachable.String())
	assert.Equal(t, "too-big", KindTooBig.String())
	assert.Equal(t, "no-buffer", KindNoBuffer.String())
}
