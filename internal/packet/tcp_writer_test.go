package packet

import (
	"context"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/capture"
)

// captureHandle records the frames written to it.
type captureHandle struct{ frames [][]byte }

func (h *captureHandle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	return nil, gopacket.CaptureInfo{}, nil
}

func (h *captureHandle) WritePacketData(data []byte) error {
	h.frames = append(h.frames, append([]byte(nil), data...))
	return nil
}

func (h *captureHandle) SetBPFRawInstructionFilter(
	[]capture.BPFInstruction,
) error {
	return nil
}

func (h *captureHandle) ClearBPF() error { return nil }

func (h *captureHandle) LinkType() layers.LinkType { return layers.LinkTypeEthernet }
func (h *captureHandle) Close()                    {}

func writeFake(
	t *testing.T,
	src, dst string,
	fake TCPFake,
) (*layers.TCP, gopacket.Packet) {
	t.Helper()

	h := &captureHandle{}
	mac := net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	w := NewTCPWriter(zerolog.Nop(), h, &net.Interface{HardwareAddr: mac}, mac)

	n, err := w.WriteCraftedPacketWithSeq(
		context.Background(),
		&net.TCPAddr{IP: net.ParseIP(src), Port: 50000},
		&net.TCPAddr{IP: net.ParseIP(dst), Port: 443},
		8,
		[]byte("payload"),
		fake,
	)
	require.NoError(t, err)
	assert.Equal(t, len("payload"), n)
	require.Len(t, h.frames, 1)

	pkt := gopacket.NewPacket(h.frames[0], layers.LayerTypeEthernet, gopacket.Default)
	tcp, ok := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
	require.True(t, ok)
	return tcp, pkt
}

// checksumOK reports whether tcp's checksum is valid for pkt.
func checksumOK(t *testing.T, tcp *layers.TCP, pkt gopacket.Packet) bool {
	t.Helper()
	got := tcp.Checksum
	nl := pkt.NetworkLayer()
	require.NotNil(t, nl)
	require.NoError(t, tcp.SetNetworkLayerForChecksum(nl))
	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true},
		tcp, gopacket.Payload(tcp.Payload)))
	again := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeTCP, gopacket.Default)
	return again.Layer(layers.LayerTypeTCP).(*layers.TCP).Checksum == got
}

func TestTCPWriter_BadMD5Sig(t *testing.T) {
	for name, addrs := range map[string][2]string{
		"ipv4": {"192.0.2.1", "203.0.113.1"},
		"ipv6": {"2001:db8::1", "2001:db8::2"},
	} {
		t.Run(name, func(t *testing.T) {
			seq := SeqAck{Seq: 1000, Ack: 5000}

			tcp, pkt := writeFake(
				t,
				addrs[0],
				addrs[1],
				TCPFake{SeqAck: seq, BadMD5Sig: true},
			)
			assert.Equal(t, uint32(1000), tcp.Seq)
			assert.Equal(t, uint32(5000), tcp.Ack)
			assert.Equal(t, uint8((20+MD5SigOptionLen)/4), tcp.DataOffset,
				"header grows by MD5SigOptionLen")
			require.Len(t, tcp.Options, 3)
			assert.Equal(
				t,
				layers.TCPOptionKind(layers.TCPOptionKindNop),
				tcp.Options[0].OptionType,
			)
			assert.Equal(
				t,
				layers.TCPOptionKind(layers.TCPOptionKindNop),
				tcp.Options[1].OptionType,
			)
			md5 := tcp.Options[2]
			assert.Equal(t, layers.TCPOptionKind(19), md5.OptionType)
			assert.Equal(t, uint8(18), md5.OptionLength)
			assert.Len(t, md5.OptionData, 16)
			assert.Equal(t, []byte("payload"), tcp.Payload)
			assert.True(t, checksumOK(t, tcp, pkt))

			other, _ := writeFake(
				t,
				addrs[0],
				addrs[1],
				TCPFake{SeqAck: seq, BadMD5Sig: true},
			)
			assert.NotEqual(t, md5.OptionData, other.Options[2].OptionData,
				"each packet gets a random digest")

			plain, pkt := writeFake(t, addrs[0], addrs[1], TCPFake{SeqAck: seq})
			assert.Empty(t, plain.Options)
			assert.Equal(t, uint8(5), plain.DataOffset)
			assert.True(t, checksumOK(t, plain, pkt))
		})
	}
}
