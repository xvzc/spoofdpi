package packet

import (
	"context"
	"net"
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
