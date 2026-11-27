package route

import (
	"errors"
	"fmt"
	"os"

	xroute "golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// callerRouteFlags are the flags of TableRoute.Flags that a write keeps.
// The others are the kernel's, such as RTF_LLDATA.
const callerRouteFlags = unix.RTF_PROTO1 | unix.RTF_PROTO2 | unix.RTF_PROTO3 |
	unix.RTF_BLACKHOLE | unix.RTF_REJECT

// checkFIB refuses a negative fib, which no socket option or sysctl takes.
// The kernel refuses one that is too large.
func checkFIB(fib int) error {
	if fib < 0 {
		return fmt.Errorf("fib %d: negative", fib)
	}
	return nil
}

// deleteMatchesGateway is true: FreeBSD deletes only the route through
// the gateway of a delete request that has one.
const deleteMatchesGateway = true

// linkGateway returns the sockaddr_dl of the interface with index. FreeBSD
// reads only the index of a link gateway.
func linkGateway(index int) (*xroute.LinkAddr, error) {
	return &xroute.LinkAddr{Index: index}, nil
}

// marshalRouteMessage returns the wire form of m.
func marshalRouteMessage(m *xroute.RouteMessage) ([]byte, error) {
	return m.Marshal()
}

// setRouteSocketFIB makes the routing socket fd write to the routing table
// of fib. A new socket uses the FIB of the process.
func setRouteSocketFIB(fd, fib int) error {
	err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SETFIB, fib)
	if err != nil {
		return os.NewSyscallError("setsockopt SO_SETFIB", err)
	}
	return nil
}

// routeDumpTries bounds the reads of a routing table dump that grows
// between sizing it and reading it.
const routeDumpTries = 3

// fetchRouteDump returns the routing table dump of address family af in
// fib. The FIB is the extra element of the NET_RT_DUMP name, after its
// argument; x/net/route's FetchRIB cannot pass it. FreeBSD names the
// PF_ROUTE node (CTL_NET.PF_ROUTE) "net.routetable"; "net.route" there is an
// unrelated node of routing tunables, unlike on darwin.
func fetchRouteDump(af, fib int) ([]byte, error) {
	for try := 1; ; try++ {
		b, err := unix.SysctlRaw("net.routetable", 0, af, unix.NET_RT_DUMP, 0, fib)
		if errors.Is(err, unix.ENOMEM) && try < routeDumpTries {
			continue
		}
		if err != nil {
			return nil, os.NewSyscallError("sysctl", err)
		}
		return b, nil
	}
}
