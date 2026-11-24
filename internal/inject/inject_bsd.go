//go:build darwin || freebsd

package inject

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/xvzc/spoofdpi/internal/netutil"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Raw sockets on darwin and FreeBSD. FreeBSD shares this code but is
// experimental: it has not been tested there.
//
//   - IPv4 uses one "ip4:255" socket with IP_HDRINCL, through
//     ipv4.RawConn. Its header marshaling writes ip_len and ip_off in the
//     byte order the kernel expects: host order on darwin and on FreeBSD
//     before 11, network order from FreeBSD 11 on. The kernel fills the IP
//     ID and the header checksum.
//   - IPv6 has no header-include option (RFC 3542). It uses one raw
//     socket per transport protocol, and the hop limit and the source go
//     with each packet as IPV6_HOPLIMIT and IPV6_PKTINFO ancillary data.
//     The kernel leaves the transport checksum as it is given, since
//     IPV6_CHECKSUM is off by default on raw sockets other than ICMPv6.

// protoTCP and protoUDP are the transport protocols a Packet can carry.
const (
	protoTCP = 6
	protoUDP = 17
)

// Open opens the raw sockets of a Sender of fam. It returns ErrNeedsRoot,
// wrapped, when the process lacks the privileges to open them.
func Open(fam netutil.Family, opts Options) (Sender, error) {
	// Each case returns a nil interface on error, not a typed nil pointer.
	switch fam {
	case netutil.FamilyV4:
		s, err := openV4(opts)
		if err != nil {
			return nil, err
		}
		return s, nil
	case netutil.FamilyV6:
		s, err := openV6(opts)
		if err != nil {
			return nil, err
		}
		return s, nil
	default:
		return nil, fmt.Errorf("open sender: unknown family %v", fam)
	}
}

// listenRaw opens a raw IP socket of network, such as "ip4:255", with
// opts.Control applied to it.
func listenRaw(network, address string, opts Options) (*net.IPConn, error) {
	lc := net.ListenConfig{Control: opts.Control}
	pc, err := lc.ListenPacket(context.Background(), network, address)
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			return nil, fmt.Errorf("%w: %w", ErrNeedsRoot, err)
		}
		return nil, fmt.Errorf("open %s raw socket: %w", network, err)
	}
	return pc.(*net.IPConn), nil
}

// v4Sender sends IPv4 packets with a header it builds itself.
type v4Sender struct {
	conn *ipv4.RawConn
}

func openV4(opts Options) (*v4Sender, error) {
	pc, err := listenRaw("ip4:255", "0.0.0.0", opts)
	if err != nil {
		return nil, err
	}
	rc, err := ipv4.NewRawConn(pc)
	if err != nil {
		_ = pc.Close()
		return nil, fmt.Errorf("set IP_HDRINCL: %w", err)
	}
	return &v4Sender{conn: rc}, nil
}

func (s *v4Sender) Send(p Packet) error {
	if err := checkPacket(p, netutil.FamilyV4); err != nil {
		return NewSendError(p.Dst, err)
	}
	if err := s.conn.WriteTo(ipv4Header(p), p.L4, nil); err != nil {
		return NewSendError(p.Dst, err)
	}
	return nil
}

func (s *v4Sender) Close() error { return s.conn.Close() }

// ipv4Header returns the IPv4 header of p: no options, no DF, and an ID
// and a checksum of 0 for the kernel to fill.
func ipv4Header(p Packet) *ipv4.Header {
	return &ipv4.Header{
		Version:  ipv4.Version,
		Len:      ipv4.HeaderLen,
		TotalLen: ipv4.HeaderLen + len(p.L4),
		TTL:      int(p.HopLimit),
		Protocol: int(p.Proto),
		Src:      p.Src.AsSlice(),
		Dst:      p.Dst.AsSlice(),
	}
}

// v6Sender sends IPv6 packets through one raw socket per transport
// protocol, which the kernel builds the header for.
type v6Sender struct {
	tcp, udp *ipv6.PacketConn
}

// v6ReadBuffer is the receive buffer of the IPv6 raw sockets, which are
// never read. The kernel raises it to its minimum.
const v6ReadBuffer = 1

func openV6(opts Options) (*v6Sender, error) {
	tcp, err := openV6Conn("ip6:tcp", opts)
	if err != nil {
		return nil, err
	}
	udp, err := openV6Conn("ip6:udp", opts)
	if err != nil {
		_ = tcp.Close()
		return nil, err
	}
	return &v6Sender{tcp: tcp, udp: udp}, nil
}

func openV6Conn(network string, opts Options) (*ipv6.PacketConn, error) {
	pc, err := listenRaw(network, "::", opts)
	if err != nil {
		return nil, err
	}
	// Only a buffer for packets the socket is not expected to receive:
	// the default buffer works too.
	_ = pc.SetReadBuffer(v6ReadBuffer)
	return ipv6.NewPacketConn(pc), nil
}

func (s *v6Sender) Send(p Packet) error {
	if err := checkPacket(p, netutil.FamilyV6); err != nil {
		return NewSendError(p.Dst, err)
	}
	conn := s.tcp
	if p.Proto == protoUDP {
		conn = s.udp
	}
	dst := &net.IPAddr{IP: p.Dst.AsSlice(), Zone: p.Dst.Zone()}
	if _, err := conn.WriteTo(p.L4, ipv6Control(p), dst); err != nil {
		return NewSendError(p.Dst, err)
	}
	return nil
}

func (s *v6Sender) Close() error {
	return errors.Join(s.tcp.Close(), s.udp.Close())
}

// ipv6Control returns the ancillary data that sets the hop limit and the
// source of p. The flow label stays 0.
func ipv6Control(p Packet) *ipv6.ControlMessage {
	return &ipv6.ControlMessage{
		HopLimit: int(p.HopLimit),
		Src:      p.Src.AsSlice(),
	}
}

// checkPacket reports why p cannot be sent by a sender of fam, including
// the hop limit of 0 that Packet refuses.
func checkPacket(p Packet, fam netutil.Family) error {
	is4 := fam == netutil.FamilyV4
	if !p.Src.IsValid() || !p.Dst.IsValid() || p.Src.Is4() != is4 || p.Dst.Is4() != is4 {
		return fmt.Errorf("addresses %v -> %v are not %v", p.Src, p.Dst, fam)
	}
	if p.Proto != protoTCP && p.Proto != protoUDP {
		return fmt.Errorf("unsupported protocol %d", p.Proto)
	}
	if p.HopLimit == 0 {
		return errors.New("hop limit 0")
	}
	return nil
}
