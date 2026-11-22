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
