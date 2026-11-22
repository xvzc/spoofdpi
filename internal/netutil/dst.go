package netutil

import (
	"fmt"
	"net"
	"strconv"
)

// Destination identifies *where* to dial — domain name, candidate
// IPs, and port. Per-dial concerns (timeout, bind hook, etc.) are
// passed to DialFastest separately so a Destination value can be
// reused across rule lookups without carrying stale settings.
type Destination struct {
	Host  string
	Addrs []net.IP
	// Zone is the IPv6 zone, such as an interface name, that the link-local
	// addresses in Addrs are dialed with. net.IP has no zone, so it is
	// kept here; it is set only for an address given as a literal.
	Zone string
	Port int
}

func (d *Destination) String() string {
	return net.JoinHostPort(d.Host, strconv.Itoa(d.Port))
}

// IsValid reports whether d may be dialed by a proxy listening on
// listenAddr. It refuses an unspecified address (0.0.0.0, ::) on any port,
// as Go dials it as the local host, and a loopback or local interface
// address on the listen port, which is the proxy itself.
func (d *Destination) IsValid(listenAddr *net.TCPAddr) (bool, error) {
	for _, ip := range d.Addrs {
		if ip.IsUnspecified() {
			return false, fmt.Errorf("unspecified addr detected %v", ip.String())
		}
	}

	if d.Port != listenAddr.Port {
		return true, nil
	}

	ifAddrs, err := net.InterfaceAddrs()
	if err != nil {
		return false, err
	}

	for _, dstAddr := range d.Addrs {
		ip := dstAddr
		if ip.IsLoopback() {
			return false, fmt.Errorf("loopback addr detected %v", ip.String())
		}

		for _, addr := range ifAddrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ipnet.IP.Equal(ip) {
					return false, fmt.Errorf("interface addr detected %v", ipnet.String())
				}
			}
		}
	}

	return true, nil
}
