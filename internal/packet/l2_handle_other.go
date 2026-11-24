//go:build !linux

package packet

import (
	"fmt"
	"net"

	"github.com/xvzc/spoofdpi/internal/capture"
)

// rejectAllFilter is a BPF program that passes no packet up.
var rejectAllFilter = []capture.BPFInstruction{
	{Op: 0x06, K: 0}, // ret #0
}

// openWriteHandle opens a handle on iface that is only written to. A pcap
// handle captures from the start, so a filter that passes nothing keeps
// the captured traffic from queuing up unread.
func openWriteHandle(iface *net.Interface) (capture.Handle, error) {
	handle, err := capture.NewHandle(iface)
	if err != nil {
		return nil, err
	}
	if err := handle.SetBPFRawInstructionFilter(rejectAllFilter); err != nil {
		handle.Close()
		return nil, fmt.Errorf("set write-only filter: %w", err)
	}
	return handle, nil
}
