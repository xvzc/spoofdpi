//go:build network

package capture

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestNewHandleWithReadTimeout_live opens a real capture handle on the
// loopback interface, so it needs root.
func TestNewHandleWithReadTimeout_live(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}

	ifaces, err := net.Interfaces()
	require.NoError(t, err)
	var lo *net.Interface
	for i := range ifaces {
		if ifaces[i].Flags&net.FlagLoopback != 0 {
			lo = &ifaces[i]
			break
		}
	}
	if lo == nil {
		t.Skip("no loopback interface")
	}

	h, err := NewHandleWithReadTimeout(lo, 200*time.Millisecond)
	require.NoError(t, err)
	defer h.Close()

	// Accept nothing, so the read can only end by timing out.
	reject := []BPFInstruction{{Op: 0x6, Jt: 0, Jf: 0, K: 0}}
	require.NoError(t, h.SetBPFRawInstructionFilter(reject))

	start := time.Now()
	_, _, err = h.ReadPacketData()
	require.Error(t, err)
	require.True(t, IsReadTimeout(err), "got %v", err)
	require.Less(t, time.Since(start), 2*time.Second)
}
