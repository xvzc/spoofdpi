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
		seq TCPSeq,
	) (int, error)
}
