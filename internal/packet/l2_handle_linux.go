//go:build linux

package packet

import (
	"net"

	"github.com/xvzc/spoofdpi/internal/capture"
)

// openWriteHandle opens a handle on iface that is only written to. On
// Linux the kernel delivers it no packets at all.
func openWriteHandle(iface *net.Interface) (capture.Handle, error) {
	return capture.NewWriteHandle(iface)
}
