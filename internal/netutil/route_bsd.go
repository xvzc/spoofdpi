//go:build darwin || freebsd

package netutil

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync/atomic"
	"time"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// errRTMNotFound is returned by rtmGet when the kernel has no matching
// route.
var errRTMNotFound = errors.New("not in table")

// rtmReplyTimeout bounds the wait for the kernel's reply to RTM_GET.
const rtmReplyTimeout = 2 * time.Second

// rtmSeq numbers the RTM_GET requests of this process, so each reply can
// be told apart from the other messages on the routing socket.
var rtmSeq atomic.Uint32

func routeTo(dst netip.Addr) (kernelRoute, error) {
	addrs := []route.Addr{
		unix.RTAX_DST: routeAddr(dst),
		// An empty link address asks the kernel to report the output
		// interface and its address.
		unix.RTAX_IFP: &route.LinkAddr{},
	}
	af := unix.AF_INET
	if dst.Is6() {
		af = unix.AF_INET6
	}
	m, err := rtmGet(af, unix.RTF_UP|unix.RTF_HOST, addrs)
	if errors.Is(err, errRTMNotFound) {
		return kernelRoute{}, errNoRoute(dst)
	}
	if err != nil {
		return kernelRoute{}, fmt.Errorf("route lookup %s: %w", dst, err)
	}
	return kernelRouteFromReply(m, dst)
}

// rtmGet sends one RTM_GET request with flags and addrs over a routing
// socket of address family af and returns the kernel's reply to it. The
// whole exchange is bounded by rtmReplyTimeout.
func rtmGet(af, flags int, addrs []route.Addr) (*route.RouteMessage, error) {
	deadline := time.Now().Add(rtmReplyTimeout)
	// The protocol af limits the messages the socket receives to that
	// family; the reply is of it too.
	fd, err := routeSocket(af)
	if err != nil {
		return nil, os.NewSyscallError("socket", err)
	}
	defer func() { _ = unix.Close(fd) }()

	pid, seq := os.Getpid(), int(rtmSeq.Add(1))
	req := &route.RouteMessage{
		Version: unix.RTM_VERSION,
		Type:    unix.RTM_GET,
		Flags:   flags,
		ID:      uintptr(pid),
		Seq:     seq,
		Addrs:   addrs,
	}
	b, err := req.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal RTM_GET: %w", err)
	}
	// The kernel reports a failed request as the error of the write. The
	// reply's rtm_errno is not used: x/net/route reads RouteMessage.Err
	// from the wrong offset.
	if _, err := unix.Write(fd, b); err != nil {
		if errors.Is(err, unix.ESRCH) {
			return nil, errRTMNotFound
		}
		return nil, os.NewSyscallError("write", err)
	}

	buf := make([]byte, os.Getpagesize())
	var parseErr error
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, rtmTimeoutError(parseErr)
		}
		// SO_RCVTIMEO bounds one read only, so it is set to what is left
		// of the deadline before each. A zero timeout would mean none.
		tv := unix.NsecToTimeval(max(remaining, time.Millisecond).Nanoseconds())
		err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
		if err != nil {
			return nil, os.NewSyscallError("setsockopt", err)
		}

		n, err := unix.Read(fd, buf)
		switch {
		case errors.Is(err, unix.EINTR):
			continue
		case errors.Is(err, unix.EAGAIN):
			return nil, rtmTimeoutError(parseErr)
		case err != nil:
			return nil, os.NewSyscallError("read", err)
		}
		// The socket also carries the other routing messages of the
		// system. One that does not parse is skipped, and its error is
		// reported if the reply never comes.
		msgs, err := route.ParseRIB(route.RIBTypeRoute, buf[:n])
		if err != nil {
			parseErr = err
			continue
		}
		if m := matchRTMReply(msgs, pid, seq); m != nil {
			return m, nil
		}
	}
}

// rtmTimeoutError returns the error for an RTM_GET reply that did not come
// in time. parseErr is the last message that failed to parse, if any.
func rtmTimeoutError(parseErr error) error {
	err := fmt.Errorf(
		"no RTM_GET reply from the routing socket within %s",
		rtmReplyTimeout,
	)
	if parseErr != nil {
		return fmt.Errorf("%w (last unparsable message: %w)", err, parseErr)
	}
	return err
}

// matchRTMReply returns the reply to the RTM_GET request of pid and seq
// among msgs, or nil if there is none.
func matchRTMReply(msgs []route.Message, pid, seq int) *route.RouteMessage {
	for _, msg := range msgs {
		m, ok := msg.(*route.RouteMessage)
		if ok && m.Type == unix.RTM_GET && m.ID == uintptr(pid) && m.Seq == seq {
			return m
		}
	}
	return nil
}

// kernelRouteFromReply reads the route to dst from m, the kernel's reply
// to RTM_GET. A reject or blackhole route counts as no route. Scoped
// routes (RTF_IFSCOPE) are kept: they are what the kernel chose. The
// gateway counts only on a route with RTF_GATEWAY and when it is an IP
// address; a link-layer gateway means an interface route. The source is
// the interface address when it is of dst's family and not link-local.
func kernelRouteFromReply(
	m *route.RouteMessage,
	dst netip.Addr,
) (kernelRoute, error) {
	if m.Flags&(unix.RTF_REJECT|unix.RTF_BLACKHOLE) != 0 {
		return kernelRoute{}, errNoRoute(dst)
	}

	kr := kernelRoute{ifIndex: m.Index}
	ifp, ok := ribAddr(m.Addrs, unix.RTAX_IFP).(*route.LinkAddr)
	if ok && ifp.Index > 0 {
		kr.ifIndex = ifp.Index
	}
	if kr.ifIndex <= 0 {
		return kernelRoute{}, fmt.Errorf("route lookup %s: no output interface", dst)
	}
	if m.Flags&unix.RTF_GATEWAY != 0 {
		kr.gateway = addrIP(ribAddr(m.Addrs, unix.RTAX_GATEWAY))
	}
	// RTAX_IFA is the route's interface address, not a source chosen by
	// RFC 6724. A link-local one is not a usable source for dst.
	ifa := addrIP(ribAddr(m.Addrs, unix.RTAX_IFA))
	if ifa.IsValid() && ifa.Is4() == dst.Is4() && !ifa.IsLinkLocalUnicast() {
		kr.src = ifa
	}
	return kr, nil
}

// routeAddr returns addr as a routing socket address.
func routeAddr(addr netip.Addr) route.Addr {
	if addr.Is4() {
		return &route.Inet4Addr{IP: addr.As4()}
	}
	return &route.Inet6Addr{IP: addr.As16()}
}

// ribAddr returns the address at index i of addrs, or nil if there is
// none.
func ribAddr(addrs []route.Addr, i int) route.Addr {
	if i < len(addrs) {
		return addrs[i]
	}
	return nil
}

// addrIP returns a as an IP address without zone, or the zero Addr if it
// is not one. x/net/route has already moved the scope that the kernel
// embeds in a link-local address out of it.
func addrIP(a route.Addr) netip.Addr {
	switch a := a.(type) {
	case *route.Inet4Addr:
		return netip.AddrFrom4(a.IP)
	case *route.Inet6Addr:
		return netip.AddrFrom16(a.IP)
	default:
		return netip.Addr{}
	}
}
