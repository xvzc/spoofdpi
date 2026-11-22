package server

import (
	"net"
	"strconv"
)

// PACProxyHostPort returns the host:port that a PAC file on this machine
// points at to reach a proxy listening on listen. An unspecified address
// (0.0.0.0, ::) becomes 127.0.0.1, which a Go listener on either accepts;
// any other address is used as it is, with brackets for IPv6.
func PACProxyHostPort(listen net.TCPAddr) string {
	port := strconv.Itoa(listen.Port)
	if listen.IP == nil || listen.IP.IsUnspecified() {
		return net.JoinHostPort("127.0.0.1", port)
	}
	return net.JoinHostPort(listen.IP.String(), port)
}
