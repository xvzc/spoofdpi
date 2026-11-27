//go:build darwin || freebsd || linux

package netutil

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// DisableAutoFlowLabel sets IPV6_AUTOFLOWLABEL to 0 on c, a socket of
// network as a socket control gets it, when it is an IPv6 socket, so that
// its packets carry flow label 0 and not one the kernel picks. It leaves
// an IPv4 socket as it is.
//
// It must run before the socket connects or first sends: darwin and
// FreeBSD pick the label then. Linux picks it per packet, and still sets
// one when net.ipv6.auto_flowlabels is 3.
func DisableAutoFlowLabel(network string, c syscall.RawConn) error {
	if !isIPv6Socket(network) {
		return nil
	}
	var sockErr error
	err := c.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_AUTOFLOWLABEL, 0)
	})
	if err != nil {
		return fmt.Errorf("failed to control socket: %w", err)
	}
	if sockErr != nil {
		return fmt.Errorf("failed to set IPV6_AUTOFLOWLABEL: %w", sockErr)
	}
	return nil
}
