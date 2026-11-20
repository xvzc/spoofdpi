package netutil

import (
	"errors"
	"net"
	"syscall"
)

// maxICMPErrors bounds how many ICMP-induced errors in a row a
// ICMPTolerantConn skips before returning one, so that a socket that keeps
// failing cannot spin forever.
const maxICMPErrors = 64

// isICMPError reports whether err is an error a connected UDP socket
// reports after receiving an ICMP message for an earlier datagram.
func isICMPError(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH)
}

// ICMPTolerantConn wraps a connected UDP socket and skips the errors it
// reports for ICMP messages.
//
// Fake packets are sent on the same flow as the real datagrams but with a
// low TTL, so routers answer them with ICMP Time Exceeded. Some systems
// (macOS among them) report that to the socket as "no route to host" on
// the next read or write, which would otherwise end a healthy flow. UDP
// flows end on their idle timeout anyway, so skipping these errors loses
// nothing but an early close.
type ICMPTolerantConn struct {
	net.Conn
}

// NewICMPTolerantConn wraps conn, a connected UDP socket.
func NewICMPTolerantConn(conn net.Conn) *ICMPTolerantConn {
	return &ICMPTolerantConn{Conn: conn}
}

func (c *ICMPTolerantConn) Read(b []byte) (int, error) {
	for i := 0; ; i++ {
		n, err := c.Conn.Read(b)
		if err == nil || !isICMPError(err) || i >= maxICMPErrors {
			return n, err
		}
	}
}

func (c *ICMPTolerantConn) Write(b []byte) (int, error) {
	for i := 0; ; i++ {
		// A pending ICMP error is returned instead of sending; retry so the
		// datagram still goes out.
		n, err := c.Conn.Write(b)
		if err == nil || !isICMPError(err) || i >= maxICMPErrors {
			return n, err
		}
	}
}
