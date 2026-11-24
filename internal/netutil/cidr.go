package netutil

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// tunCandidateRanges are the ranges, in order, that FindSafeCIDR walks in
// /30 steps from their start for the TUN's subnet.
var tunCandidateRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
}

// tunSubnetBits is the prefix length of the TUN's subnet: its local
// address is the subnet's first host and the remote address the second.
const tunSubnetBits = 30

// tunMaxNoRouteRun is how many candidates in a row of one range may have
// no route before FindSafeCIDR gives up on the range. Linux answers a
// lookup that hits a blackhole, unreachable or prohibit route with an
// errno alone, without the route's prefix, so the walk cannot jump past
// it. Hosts that blackhole a whole range, such as 10.0.0.0/8 against
// RFC 1918 leaks, would otherwise cost a lookup per /30: 2^22 in 10/8.
const tunMaxNoRouteRun = 256

// osRoutePrefix asks the kernel for the prefix of the route it matches for
// dst. It returns ErrNoIPv4Route or ErrNoIPv6Route, wrapped, when there is
// none or the route rejects or drops dst; a *rejectRouteError carries that
// route's prefix when the kernel reports it. Tests replace it.
var osRoutePrefix = routePrefixTo

// FindSafeCIDR returns a /30 for the TUN interface from tunCandidateRanges
// whose two host addresses are on no interface's network and are not
// routed by a route more specific than the one to the probe destination,
// such as a VPN's or a LAN's route.
func FindSafeCIDR() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}
	return findSafeCIDR(addrs, osRoutePrefix)
}

// findSafeCIDR is FindSafeCIDR for the interface addresses addrs, with
// prefixOf looking up the prefix of the route to an address.
//
// A candidate whose host addresses take the default route, or another
// route no more specific than the probe's, such as the /1 halves of a
// full-tunnel VPN, is free. When the probe's prefix is a /32, as Linux
// before 4.13 reports it because it ignores RTM_F_FIB_MATCH, no route can
// be more specific, so only interface addresses are checked. So are they
// when the probe has no route, as on a host without an IPv4 default route
// whose TUN runs with an explicit gateway: no route can then be compared.
func findSafeCIDR(
	addrs []net.Addr,
	prefixOf func(netip.Addr) (netip.Prefix, error),
) (string, error) {
	probe, err := prefixOf(probeDstV4)
	switch {
	case errors.Is(err, ErrNoIPv4Route):
		prefixOf = nil
	case err != nil:
		return "", err
	case probe.Bits() == probeDstV4.BitLen():
		prefixOf = nil
	}
	ifaceNets := interfaceNetsV4(addrs)

	var last string
	for _, r := range tunCandidateRanges {
		noRouteRun := 0
		for start := r.Addr(); r.Contains(start); {
			subnet := netip.PrefixFrom(start, tunSubnetBits)
			c, err := tunSubnetConflict(subnet, ifaceNets, probe, prefixOf)
			if err != nil {
				return "", err
			}
			if !c.taken.IsValid() {
				return subnet.String(), nil
			}
			last = c.reason
			if !c.noRoute {
				noRouteRun = 0
			} else if noRouteRun++; noRouteRun == tunMaxNoRouteRun {
				last = fmt.Sprintf(
					"%s: %d candidates in a row have no route", r, tunMaxNoRouteRun,
				)
				break
			}
			start = lastAddrV4(c.taken).Next()
		}
	}

	ranges := make([]string, len(tunCandidateRanges))
	for i, r := range tunCandidateRanges {
		ranges[i] = r.String()
	}
	return "", fmt.Errorf(
		"no free /%d for the TUN interface in %s or %s: every candidate overlaps "+
			"an interface address or a more specific route (last: %s)",
		tunSubnetBits,
		strings.Join(ranges[:len(ranges)-1], ", "),
		ranges[len(ranges)-1],
		last,
	)
}

// tunConflict is what takes a candidate subnet of the TUN.
type tunConflict struct {
	// taken is the range that takes the subnet, which covers the subnet
	// itself when the range is smaller; the zero Prefix when it is free.
	taken  netip.Prefix
	reason string
	// noRoute reports a host address without a route whose prefix is
	// unknown, so that taken is the subnet alone.
	noRoute bool
}

// tunSubnetConflict returns what takes subnet, or a zero tunConflict when
// subnet is free. An interface network takes it when it holds one of
// subnet's host addresses. With prefixOf, so does a route to one of them
// that is more specific than probe, the prefix of the route to the probe
// destination, and so does no route.
func tunSubnetConflict(
	subnet netip.Prefix,
	ifaceNets []netip.Prefix,
	probe netip.Prefix,
	prefixOf func(netip.Addr) (netip.Prefix, error),
) (tunConflict, error) {
	local := subnet.Addr().Next()
	hosts := []netip.Addr{local, local.Next()}

	for _, n := range ifaceNets {
		if n.Contains(hosts[0]) || n.Contains(hosts[1]) {
			return tunConflict{
				taken:  widest(subnet, n),
				reason: fmt.Sprintf("%s overlaps interface network %s", subnet, n),
			}, nil
		}
	}
	if prefixOf == nil {
		return tunConflict{}, nil
	}
	for _, h := range hosts {
		p, err := prefixOf(h)
		var reject *rejectRouteError
		if errors.As(err, &reject) {
			return tunConflict{
				taken:  widest(subnet, reject.prefix),
				reason: fmt.Sprintf("%s: %v", subnet, err),
			}, nil
		}
		if errors.Is(err, ErrNoIPv4Route) {
			return tunConflict{
				taken:   subnet,
				reason:  fmt.Sprintf("%s: %v", subnet, err),
				noRoute: true,
			}, nil
		}
		if err != nil {
			return tunConflict{}, err
		}
		if p.Bits() > probe.Bits() {
			return tunConflict{
				taken: widest(subnet, p),
				reason: fmt.Sprintf(
					"%s is routed by %s, more specific than %s", subnet, p, probe,
				),
			}, nil
		}
	}
	return tunConflict{}, nil
}

// widest returns the wider of subnet and p, which overlap, masked.
func widest(subnet, p netip.Prefix) netip.Prefix {
	if p.Bits() < subnet.Bits() {
		return p.Masked()
	}
	return subnet
}

// lastAddrV4 returns the last address of p, an IPv4 prefix.
func lastAddrV4(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().As4()
	v := binary.BigEndian.Uint32(b[:]) | ^uint32(0)>>p.Bits()
	return netip.AddrFrom4([4]byte(binary.BigEndian.AppendUint32(nil, v)))
}

// interfaceNetsV4 returns the IPv4 networks of addrs, the interface
// addresses. One with a mask that is not an IPv4 prefix counts as its
// address alone.
func interfaceNetsV4(addrs []net.Addr) []netip.Prefix {
	var nets []netip.Prefix
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(n.IP.To4())
		if !ok {
			continue
		}
		ones, bits := n.Mask.Size()
		if bits != ip.BitLen() {
			ones = ip.BitLen()
		}
		nets = append(nets, netip.PrefixFrom(ip, ones).Masked())
	}
	return nets
}

func AddrInCIDR(cidr string, n int) (string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", err
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return "", fmt.Errorf("not an IPv4 CIDR")
	}

	ipInt := binary.BigEndian.Uint32(ip4)

	resultInt := ipInt + uint32(n)

	resultIP := make(net.IP, 4)
	binary.BigEndian.PutUint32(resultIP, resultInt)

	if !ipnet.Contains(resultIP) {
		return "", fmt.Errorf("index %d is out of CIDR range %s", n, cidr)
	}

	return resultIP.String(), nil
}
