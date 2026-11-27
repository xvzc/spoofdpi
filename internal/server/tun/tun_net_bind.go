//go:build darwin || linux || freebsd

package tun

import (
	"fmt"
	"net"
	"strings"
	"syscall"

	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/route"
)

// egressFor returns the egress of target's family, egress4 or egress6, or
// an error when that family has none.
func egressFor(egress4, egress6 *route.Route, target net.IP) (*route.Route, error) {
	rt, fam := egress4, netutil.FamilyV4
	if target.To4() == nil {
		rt, fam = egress6, netutil.FamilyV6
	}
	if rt == nil || rt.Iface.Name == "" {
		return nil, fmt.Errorf("no %s egress for target %s", fam, target)
	}
	return rt, nil
}

// bindEgress pins dialer to rt, the egress of target's family, with
// control. An IPv4 dial also leaves from the first IPv4 address of rt's
// interface. An IPv6 dial leaves the source address to the kernel: the
// first IPv6 address of the interface may be link-local or temporary.
func bindEgress(
	dialer *net.Dialer,
	network string,
	target net.IP,
	rt *route.Route,
	control func(network, address string, c syscall.RawConn) error,
) error {
	if target.To4() == nil {
		dialer.Control = control
		return nil
	}

	addrs, err := rt.Iface.Addrs()
	if err != nil {
		return fmt.Errorf("failed to get interface addresses: %w", err)
	}

	var sourceIP net.IP
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok &&
			ipnet.IP.To4() != nil && !ipnet.IP.IsLoopback() {
			sourceIP = ipnet.IP
			break
		}
	}

	if sourceIP == nil {
		return fmt.Errorf(
			"no suitable IP address found on interface %s for target %s",
			rt.Iface.Name,
			target,
		)
	}

	if strings.HasPrefix(network, "tcp") {
		dialer.LocalAddr = &net.TCPAddr{IP: sourceIP}
	} else if strings.HasPrefix(network, "udp") {
		dialer.LocalAddr = &net.UDPAddr{IP: sourceIP}
	} else {
		dialer.LocalAddr = &net.IPAddr{IP: sourceIP}
	}

	dialer.Control = control

	return nil
}
