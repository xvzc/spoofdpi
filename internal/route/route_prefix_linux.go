package route

import (
	"fmt"
	"net/netip"
)

func routePrefixTo(dst netip.Addr) (netip.Prefix, error) {
	seq := netlinkSeq.Add(1)
	reply, err := netlinkRequest(encodeRouteFIBMatch(seq, dst), seq, false)
	if isNoRouteErrno(err, dst) {
		return netip.Prefix{}, errNoRoute(dst)
	}
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("route lookup %s: %w", dst, err)
	}
	return prefixFromNetlink(reply, dst)
}
