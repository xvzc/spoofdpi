//go:build !darwin && !freebsd && !linux

package netutil

import (
	"fmt"
	"net/netip"
	"runtime"
)

func routePrefixTo(dst netip.Addr) (netip.Prefix, error) {
	return netip.Prefix{}, fmt.Errorf(
		"route lookup %s: not supported on %s", dst, runtime.GOOS,
	)
}
