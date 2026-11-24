//go:build network && linux

package capture

import (
	"bytes"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// TestNewWriteHandle_live writes a frame to the loopback interface with a
// write handle, sees it on a capture handle, and checks that the write
// handle itself received nothing. It needs root.
func TestNewWriteHandle_live(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skipf("no lo: %v", err)
	}

	r, err := NewHandleWithReadTimeout(lo, 100*time.Millisecond)
	require.NoError(t, err)
	defer r.Close()
	w, err := NewWriteHandle(lo)
	require.NoError(t, err)
	defer w.Close()

	// An Ethernet frame of the local experimental EtherType 0x88b5.
	marker := []byte("spoofdpi write handle")
	frame := make([]byte, 14, 14+len(marker))
	frame[12], frame[13] = 0x88, 0xb5
	frame = append(frame, marker...)
	require.NoError(t, w.WritePacketData(frame))

	seen := false
	for deadline := time.Now().Add(2 * time.Second); !seen && time.Now().Before(deadline); {
		data, _, err := r.ReadPacketData()
		if IsReadTimeout(err) {
			continue
		}
		require.NoError(t, err)
		seen = bytes.Contains(data, marker)
	}
	assert.True(t, seen, "the frame reaches the interface")

	buf := make([]byte, 2048)
	_, _, err = unix.Recvfrom(w.(*LinuxHandle).fd, buf, unix.MSG_DONTWAIT)
	assert.True(
		t,
		errors.Is(err, unix.EAGAIN),
		"the write handle receives nothing: %v",
		err,
	)
}
