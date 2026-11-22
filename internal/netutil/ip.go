package netutil

import (
	"net"
	"net/netip"
)

// IPsFromAddrs returns addrs as net.IP values, in the same order.
func IPsFromAddrs(addrs []netip.Addr) []net.IP {
	ips := make([]net.IP, len(addrs))
	for i, a := range addrs {
		ips[i] = a.AsSlice()
	}

	return ips
}

// NeedsZone reports whether ip is an IPv6 link-local unicast address, which
// is reachable only through the interface that a zone names.
func NeedsZone(ip net.IP) bool {
	return ip.To4() == nil && ip.IsLinkLocalUnicast()
}
