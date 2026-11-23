package netutil

import (
	"fmt"
	"net/netip"
	"runtime"
)

func routeTo(dst netip.Addr) (kernelRoute, error) {
	return kernelRoute{}, fmt.Errorf(
		"route lookup %s: not supported on %s", dst, runtime.GOOS,
	)
}
