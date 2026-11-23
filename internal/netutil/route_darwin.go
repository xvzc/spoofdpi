package netutil

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// routeSocket opens a routing socket of address family af, closed on exec.
// darwin has no SOCK_CLOEXEC, so the fork lock keeps a concurrent fork
// from inheriting the descriptor before it is marked.
func routeSocket(af int) (int, error) {
	syscall.ForkLock.RLock()
	defer syscall.ForkLock.RUnlock()
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, af)
	if err != nil {
		return -1, err
	}
	unix.CloseOnExec(fd)
	return fd, nil
}
