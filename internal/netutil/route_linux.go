package netutil

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// netlinkReplyTimeout bounds the wait for the kernel's answer to a
// netlink request.
const netlinkReplyTimeout = 2 * time.Second

// netlinkSeq numbers the netlink requests of this process.
var netlinkSeq atomic.Uint32

func routeTo(dst netip.Addr) (kernelRoute, error) {
	seq := netlinkSeq.Add(1)
	reply, err := netlinkRequest(encodeRouteGet(seq, dst), seq, false)
	if isNoRouteErrno(err, dst) {
		return kernelRoute{}, errNoRoute(dst)
	}
	if err != nil {
		return kernelRoute{}, fmt.Errorf("route lookup %s: %w", dst, err)
	}
	return kernelRouteFromNetlink(reply, dst)
}

// netlinkRequest sends req, numbered seq, on a new NETLINK_ROUTE socket and
// returns the kernel's answer: one message, or every message of a dump.
func netlinkRequest(req []byte, seq uint32, dump bool) ([]netlinkMessage, error) {
	fd, err := unix.Socket(
		unix.AF_NETLINK,
		unix.SOCK_RAW|unix.SOCK_CLOEXEC,
		unix.NETLINK_ROUTE,
	)
	if err != nil {
		return nil, os.NewSyscallError("socket", err)
	}
	defer func() { _ = unix.Close(fd) }()

	tv := unix.NsecToTimeval(netlinkReplyTimeout.Nanoseconds())
	err = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	if err != nil {
		return nil, os.NewSyscallError("setsockopt", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, os.NewSyscallError("bind", err)
	}
	sa, err := unix.Getsockname(fd)
	if err != nil {
		return nil, os.NewSyscallError("getsockname", err)
	}
	nlsa, ok := sa.(*unix.SockaddrNetlink)
	if !ok {
		return nil, fmt.Errorf("netlink: socket address of type %T", sa)
	}

	kernel := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := unix.Sendto(fd, req, 0, kernel); err != nil {
		return nil, os.NewSyscallError("sendto", err)
	}

	var reply []netlinkMessage
	buf := make([]byte, 64<<10)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		switch {
		case errors.Is(err, unix.EINTR):
			continue
		case errors.Is(err, unix.EAGAIN):
			return nil, errors.New("netlink: no reply")
		case err != nil:
			return nil, os.NewSyscallError("recvfrom", err)
		}
		msgs, err := parseNetlinkMessages(buf[:n])
		if err != nil {
			return nil, err
		}
		var done bool
		reply, done, err = collectReply(reply, msgs, seq, nlsa.Pid, dump)
		if done || err != nil {
			return reply, err
		}
	}
}
