// Package inject sends packets that spoofdpi builds itself, such as fake
// TCP segments, through the kernel's IP layer with raw sockets. The
// kernel routes them and resolves the next hop.
package inject

import (
	"errors"
	"fmt"
	"net/netip"
	"syscall"
)

// Packet is one IP packet to send. The sender builds the IP header.
type Packet struct {
	// Src and Dst are of the same family. Src is the local address of the
	// real connection the packet belongs to.
	Src, Dst netip.Addr
	// Proto is the transport protocol: 6 (TCP) or 17 (UDP).
	Proto uint8
	// HopLimit is the IPv4 TTL or the IPv6 hop limit.
	HopLimit uint8
	// L4 is the transport header and payload, with its checksum already
	// computed over Src and Dst.
	L4 []byte
}

// Sender sends packets of one address family.
type Sender interface {
	// Send sends p once, without retrying. A failure is a *SendError.
	Send(p Packet) error
	Close() error
}

// Options configures the raw sockets of a Sender.
type Options struct {
	// Control runs on every raw socket before use, like
	// net.ListenConfig.Control. nil leaves the route to the kernel; TUN
	// mode pins the sockets to the physical interface with it.
	Control func(network, address string, c syscall.RawConn) error
}

// ErrNeedsRoot is returned, wrapped, when a raw socket cannot be opened
// for lack of privileges.
var ErrNeedsRoot = errors.New("fake packets need root (raw IP socket)")

// Kind is the class of a send failure.
type Kind uint8

const (
	// KindOther is any failure not listed below.
	KindOther Kind = iota
	// KindBlocked is a local firewall drop (EPERM, EACCES).
	KindBlocked
	// KindUnreachable is no route, or a policy such as NECP that denies
	// the route (EHOSTUNREACH, ENETUNREACH).
	KindUnreachable
	// KindTooBig is a packet larger than the kernel accepts (EMSGSIZE).
	KindTooBig
	// KindNoBuffer is a full send queue (ENOBUFS).
	KindNoBuffer
)

func (k Kind) String() string {
	switch k {
	case KindBlocked:
		return "blocked"
	case KindUnreachable:
		return "unreachable"
	case KindTooBig:
		return "too-big"
	case KindNoBuffer:
		return "no-buffer"
	default:
		return "other"
	}
}

// SendError is a failure to send a packet to Dst.
type SendError struct {
	Dst  netip.Addr
	Kind Kind
	Err  error
}

// NewSendError wraps err, a failure to send a packet to dst, with the Kind
// of its errno.
func NewSendError(dst netip.Addr, err error) *SendError {
	return &SendError{Dst: dst, Kind: kindOf(err), Err: err}
}

func (e *SendError) Error() string {
	return fmt.Sprintf("send to %s (%s): %v", e.Dst, e.Kind, e.Err)
}

func (e *SendError) Unwrap() error { return e.Err }

// kindOf returns the Kind of the errno that err wraps.
func kindOf(err error) Kind {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return KindOther
	}
	switch errno {
	case syscall.EPERM, syscall.EACCES:
		return KindBlocked
	case syscall.EHOSTUNREACH, syscall.ENETUNREACH:
		return KindUnreachable
	case syscall.EMSGSIZE:
		return KindTooBig
	case syscall.ENOBUFS:
		return KindNoBuffer
	default:
		return KindOther
	}
}
