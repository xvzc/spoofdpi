package desync

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/packetio/inject"
)

type Writer interface {
	WriteCraftedPacket(
		ctx context.Context,
		src net.Addr,
		dst net.Addr,
		ttl uint8,
		payload []byte,
	) (int, error)
}

// TCPSeqWriter is a Writer that can also craft TCP packets carrying the
// given sequence numbers instead of random ones.
type TCPSeqWriter interface {
	Writer
	WriteCraftedPacketWithSeq(
		ctx context.Context,
		src net.Addr,
		dst net.Addr,
		ttl uint8,
		payload []byte,
		fake TCPFake,
	) (int, error)
}

// TCPFake sets the TCP header of a crafted fake packet.
type TCPFake struct {
	SeqAck

	// BadMD5Sig adds a TCP MD5 signature option (RFC 2385) with a random
	// digest. A server that has no MD5 key for the connection drops the
	// packet, while DPI usually ignores the option.
	BadMD5Sig bool
}

// MD5SigOptionLen is the number of bytes the MD5 signature option adds to
// the TCP header: two NOPs for alignment, then kind 19, length 18 and a
// 16-byte digest.
const MD5SigOptionLen = 20

// Senders are the senders that crafted packets leave through, one per
// address family. A nil one means packets of its family cannot be sent.
type Senders struct {
	V4, V6 inject.Sender
}

// transportLayer is a transport header whose checksum covers the IP
// pseudo-header.
type transportLayer interface {
	gopacket.SerializableLayer
	SetNetworkLayerForChecksum(gopacket.NetworkLayer) error
}

// send serializes l4 and payload as a segment of proto from src to dst,
// with its checksum over their pseudo-header, and sends it with hop limit
// ttl through the sender of dst's family. A ttl of 0 is refused, as
// inject.Packet requires.
func (s Senders) send(
	src, dst net.IP,
	ttl uint8,
	proto layers.IPProtocol,
	l4 transportLayer,
	payload []byte,
) error {
	if ttl == 0 {
		return errors.New("hop limit 0")
	}
	srcAddr, srcOK := netip.AddrFromSlice(src)
	dstAddr, dstOK := netip.AddrFromSlice(dst)
	if !srcOK || !dstOK {
		return fmt.Errorf("invalid addresses %v -> %v", src, dst)
	}
	srcAddr, dstAddr = srcAddr.Unmap(), dstAddr.Unmap()
	if srcAddr.Is4() != dstAddr.Is4() {
		return fmt.Errorf("addresses %v -> %v differ in family", srcAddr, dstAddr)
	}

	var network gopacket.NetworkLayer
	sender, fam := s.V4, netutil.FamilyV4
	if dstAddr.Is4() {
		network = &layers.IPv4{
			SrcIP:    srcAddr.AsSlice(),
			DstIP:    dstAddr.AsSlice(),
			Protocol: proto,
		}
	} else {
		sender, fam = s.V6, netutil.FamilyV6
		network = &layers.IPv6{
			SrcIP:      srcAddr.AsSlice(),
			DstIP:      dstAddr.AsSlice(),
			NextHeader: proto,
		}
	}
	if sender == nil {
		return fmt.Errorf("no %v sender for %v", fam, dstAddr)
	}

	if err := l4.SetNetworkLayerForChecksum(network); err != nil {
		return err
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	if err := gopacket.SerializeLayers(
		buf,
		opts,
		l4,
		gopacket.Payload(payload),
	); err != nil {
		return err
	}

	return sender.Send(inject.Packet{
		Src:      srcAddr,
		Dst:      dstAddr,
		Proto:    uint8(proto),
		HopLimit: ttl,
		L4:       buf.Bytes(),
	})
}
