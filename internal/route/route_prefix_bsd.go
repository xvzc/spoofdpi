//go:build darwin || freebsd

package route

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	xroute "golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func routePrefixTo(dst netip.Addr) (netip.Prefix, error) {
	addrs := []xroute.Addr{unix.RTAX_DST: routeAddr(dst)}
	af := unix.AF_INET
	if dst.Is6() {
		af = unix.AF_INET6
	}
	m, err := rtmGet(af, unix.RTF_UP|unix.RTF_HOST, addrs)
	if errors.Is(err, errRTMNotFound) {
		return netip.Prefix{}, errNoRoute(dst)
	}
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("route lookup %s: %w", dst, err)
	}
	return prefixFromReply(m, dst)
}

// prefixFromReply reads the prefix of the route that matched dst from m,
// the kernel's reply to RTM_GET. A reject or blackhole route counts as no
// route: a *rejectRouteError with the route's prefix, or the plain error
// of errNoRoute when its prefix is unreadable.
func prefixFromReply(m *xroute.RouteMessage, dst netip.Addr) (netip.Prefix, error) {
	p, err := replyPrefix(m, dst)
	if m.Flags&(unix.RTF_REJECT|unix.RTF_BLACKHOLE) != 0 {
		if err != nil {
			return netip.Prefix{}, errNoRoute(dst)
		}
		return netip.Prefix{}, &rejectRouteError{prefix: p, err: errNoRoute(dst)}
	}
	return p, err
}

// replyPrefix returns the prefix of the route in m, which matched dst. A
// host route (RTF_HOST) has no netmask and covers dst alone; other routes
// have the length of their netmask.
func replyPrefix(m *xroute.RouteMessage, dst netip.Addr) (netip.Prefix, error) {
	bits := dst.BitLen()
	if m.Flags&unix.RTF_HOST == 0 {
		mask := addrIP(ribAddr(m.Addrs, unix.RTAX_NETMASK))
		if !mask.IsValid() {
			return netip.Prefix{}, fmt.Errorf("route lookup %s: no netmask", dst)
		}
		ones, maskBits := net.IPMask(mask.AsSlice()).Size()
		if maskBits != dst.BitLen() {
			return netip.Prefix{}, fmt.Errorf(
				"route lookup %s: netmask %s is not a prefix of the address family",
				dst,
				mask,
			)
		}
		bits = ones
	}
	return netip.PrefixFrom(dst, bits).Masked(), nil
}
