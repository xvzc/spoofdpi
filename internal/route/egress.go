package route

import "net"

// ipv6EgressProbe is a global IPv6 address the kernel is asked to route
// to. Connecting a UDP socket to it sends no packet.
var ipv6EgressProbe = &net.UDPAddr{IP: net.ParseIP("2001:4860:4860::8888"), Port: 53}

// IPv6Egress reports whether the host has an IPv6 route to the internet:
// whether the kernel picks a global unicast source address for a global
// destination. src is that address. It sends no packet.
func IPv6Egress() (src net.IP, ok bool) {
	conn, err := net.DialUDP("udp6", nil, ipv6EgressProbe)
	if err != nil {
		return nil, false
	}
	defer func() { _ = conn.Close() }()

	src = conn.LocalAddr().(*net.UDPAddr).IP
	if !isIPv6EgressSource(src) {
		return nil, false
	}
	return src, true
}

// isIPv6EgressSource reports whether ip is a source address that reaches
// the internet over IPv6: a global unicast IPv6 address outside the unique
// local range (fc00::/7).
func isIPv6EgressSource(ip net.IP) bool {
	return ip.To4() == nil && ip.IsGlobalUnicast() && !ip.IsPrivate()
}
