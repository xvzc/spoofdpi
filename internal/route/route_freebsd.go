package route

import "golang.org/x/sys/unix"

// routeSocket opens a routing socket of address family af, closed on exec.
func routeSocket(af int) (int, error) {
	return unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW|unix.SOCK_CLOEXEC, af)
}
