package probe

import (
	"context"
	"net"
	"net/netip"
	"syscall"
)

// dialFunc opens a connection to addr whose packets leave with the given
// TTL, or with the system's default TTL when ttl is 0.
type dialFunc func(ctx context.Context, ttl int, addr netip.AddrPort) (net.Conn, error)

// dialer returns a dialFunc for network, "tcp4" or "udp4".
func dialer(network string) dialFunc {
	return func(ctx context.Context, ttl int, addr netip.AddrPort) (net.Conn, error) {
		d := net.Dialer{}
		if ttl > 0 {
			d.Control = ttlControl(ttl)
		}
		return d.DialContext(ctx, network, addr.String())
	}
}

// ttlControl returns a net.Dialer Control function that sets the IPv4 TTL
// of the socket. Control runs before connect, so the TTL applies to the
// TCP SYN too.
func ttlControl(ttl int) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var sockErr error
		err := c.Control(func(fd uintptr) {
			sockErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
		})
		if err != nil {
			return err
		}
		return sockErr
	}
}
