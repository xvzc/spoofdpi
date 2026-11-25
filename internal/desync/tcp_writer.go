package desync

import (
	"context"
	"errors"
	"math/rand/v2"
	"net"

	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog"
)

var _ TCPSeqWriter = (*TCPWriter)(nil)

type TCPWriter struct {
	logger zerolog.Logger

	senders Senders
}

func NewTCPWriter(logger zerolog.Logger, senders Senders) *TCPWriter {
	return &TCPWriter{
		logger:  logger,
		senders: senders,
	}
}

// --- Injector Methods ---

// WriteCraftedPacket crafts a TCP segment from a payload, with random
// sequence numbers, and sends it with TTL ttl through the sender of dst's
// family.
func (tw *TCPWriter) WriteCraftedPacket(
	ctx context.Context,
	src net.Addr,
	dst net.Addr,
	ttl uint8,
	payload []byte,
) (int, error) {
	return tw.writeCrafted(src, dst, ttl, payload, TCPFake{
		SeqAck: SeqAck{Seq: rand.Uint32(), Ack: rand.Uint32()},
	})
}

// WriteCraftedPacketWithSeq is like WriteCraftedPacket, but the packet
// carries the sequence numbers and options in fake.
func (tw *TCPWriter) WriteCraftedPacketWithSeq(
	ctx context.Context,
	src net.Addr,
	dst net.Addr,
	ttl uint8,
	payload []byte,
	fake TCPFake,
) (int, error) {
	return tw.writeCrafted(src, dst, ttl, payload, fake)
}

func (tw *TCPWriter) writeCrafted(
	src net.Addr,
	dst net.Addr,
	ttl uint8,
	payload []byte,
	fake TCPFake,
) (int, error) {
	srcTCP, ok := src.(*net.TCPAddr)
	if !ok {
		return 0, errors.New("src is not *net.TCPAddr")
	}

	dstTCP, ok := dst.(*net.TCPAddr)
	if !ok {
		return 0, errors.New("dst is not *net.TCPAddr")
	}

	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(srcTCP.Port),
		DstPort: layers.TCPPort(dstTCP.Port),
		Seq:     fake.Seq,
		PSH:     true, // Push the payload
		ACK:     true, // Assuming this is part of an established flow
		Ack:     fake.Ack,
		Window:  12345,
		Options: tcpFakeOptions(fake),
	}
	err := tw.senders.send(
		srcTCP.IP,
		dstTCP.IP,
		ttl,
		layers.IPProtocolTCP,
		tcpLayer,
		payload,
	)
	if err != nil {
		return 0, err
	}

	return len(payload), nil
}

// tcpFakeOptions returns the TCP options of a fake packet.
func tcpFakeOptions(fake TCPFake) []layers.TCPOption {
	if !fake.BadMD5Sig {
		return nil
	}

	digest := make([]byte, 16)
	for i := range digest {
		digest[i] = byte(rand.Uint32())
	}

	return []layers.TCPOption{
		{OptionType: layers.TCPOptionKindNop},
		{OptionType: layers.TCPOptionKindNop},
		{OptionType: tcpOptionKindMD5Sig, OptionLength: 18, OptionData: digest},
	}
}

// tcpOptionKindMD5Sig is the TCP MD5 signature option (RFC 2385), which
// gopacket does not name.
const tcpOptionKindMD5Sig layers.TCPOptionKind = 19
