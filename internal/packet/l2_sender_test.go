package packet

import (
	"context"
	"net"
	"net/netip"
	"syscall"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/capture"
	"github.com/xvzc/spoofdpi/internal/inject"
)

// captureHandle records the frames written to it, or fails them with
// err.
type captureHandle struct {
	frames [][]byte
	err    error
	closed bool
}

func (h *captureHandle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	return nil, gopacket.CaptureInfo{}, nil
}

func (h *captureHandle) WritePacketData(data []byte) error {
	if h.err != nil {
		return h.err
	}
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
func (h *captureHandle) Close()                    { h.closed = true }

func TestL2Sender(t *testing.T) {
	srcMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	gwMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 2}
	// A bare TCP header: 50000 -> 443, data offset 5, ACK.
	l4 := []byte{
		0xc3, 0x50, 0x01, 0xbb, 0, 0, 0, 1, 0, 0, 0, 2,
		0x50, 0x10, 0x30, 0x39, 0xbe, 0xef, 0, 0,
	}

	tcs := []struct {
		name     string
		src, dst string
		ethType  layers.EthernetType
		ipLayer  gopacket.LayerType
		noMAC    bool
	}{
		{
			name: "ipv4", src: "192.0.2.1", dst: "203.0.113.1",
			ethType: layers.EthernetTypeIPv4, ipLayer: layers.LayerTypeIPv4,
		},
		{
			name: "ipv6", src: "2001:db8::1", dst: "2001:db8::2",
			ethType: layers.EthernetTypeIPv6, ipLayer: layers.LayerTypeIPv6,
		},
		{
			name: "ipv4 without a gateway MAC", src: "192.0.2.1", dst: "203.0.113.1",
			ipLayer: layers.LayerTypeIPv4, noMAC: true,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			h := &captureHandle{}
			dstMAC := gwMAC
			if tc.noMAC {
				dstMAC = nil
			}
			s := NewL2Sender(h, srcMAC, dstMAC)
			p := inject.Packet{
				Src:      netip.MustParseAddr(tc.src),
				Dst:      netip.MustParseAddr(tc.dst),
				Proto:    6,
				HopLimit: 7,
				L4:       l4,
			}
			require.NoError(t, s.Send(p))
			require.Len(t, h.frames, 1)

			first := layers.LayerTypeEthernet
			if tc.noMAC {
				first = tc.ipLayer
			}
			pkt := gopacket.NewPacket(h.frames[0], first, gopacket.Default)
			require.Nil(t, pkt.ErrorLayer())

			eth, hasEth := pkt.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
			assert.Equal(t, !tc.noMAC, hasEth)
			if hasEth {
				assert.Equal(t, srcMAC, eth.SrcMAC)
				assert.Equal(t, gwMAC, eth.DstMAC)
				assert.Equal(t, tc.ethType, eth.EthernetType)
			}

			switch ip := pkt.Layer(tc.ipLayer).(type) {
			case *layers.IPv4:
				assert.Equal(t, uint8(7), ip.TTL)
				assert.Equal(t, layers.IPProtocolTCP, ip.Protocol)
				assert.Equal(t, net.ParseIP(tc.src).To4(), ip.SrcIP)
				assert.Equal(t, net.ParseIP(tc.dst).To4(), ip.DstIP)
				assert.Equal(t, uint16(20+len(l4)), ip.Length)
				assert.Zero(t, ip.Id)
				assert.Zero(t, ip.Flags)
				assert.Equal(t, l4, ip.Payload)
				assert.True(t, ipv4HeaderChecksumValid(ip.Contents))
			case *layers.IPv6:
				assert.Equal(t, uint8(7), ip.HopLimit)
				assert.Equal(t, layers.IPProtocolTCP, ip.NextHeader)
				assert.Equal(t, net.ParseIP(tc.src), ip.SrcIP)
				assert.Equal(t, net.ParseIP(tc.dst), ip.DstIP)
				assert.Equal(t, uint16(len(l4)), ip.Length)
				assert.Zero(t, ip.FlowLabel)
				assert.Equal(t, l4, ip.Payload)
			default:
				t.Fatalf("no %v layer", tc.ipLayer)
			}
		})
	}
}

// ipv4HeaderChecksumValid reports whether the checksum of hdr, an IPv4
// header, is valid.
func ipv4HeaderChecksumValid(hdr []byte) bool {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		sum += uint32(hdr[i])<<8 | uint32(hdr[i+1])
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return sum == 0xffff
}

func TestL2Sender_WriteError(t *testing.T) {
	h := &captureHandle{err: syscall.ENOBUFS}
	s := NewL2Sender(h, nil, nil)
	dst := netip.MustParseAddr("203.0.113.1")
	err := s.Send(inject.Packet{
		Src:      netip.MustParseAddr("192.0.2.1"),
		Dst:      dst,
		Proto:    17,
		HopLimit: 1,
	})
	var sendErr *inject.SendError
	require.ErrorAs(t, err, &sendErr)
	assert.Equal(t, inject.KindNoBuffer, sendErr.Kind)
	assert.Equal(t, dst, sendErr.Dst)
}

func TestL2Sender_Close(t *testing.T) {
	h := &captureHandle{}
	require.NoError(t, NewL2Sender(h, nil, nil).Close())
	assert.True(t, h.closed)
}

// TestL2Sender_GoldenFrames checks that a fake sent through a writer and
// an L2Sender is, byte for byte, the frame the writers built in one pass
// before they sent through inject.Sender: Ethernet, IP and transport
// layers serialized together, with the checksums computed.
func TestL2Sender_GoldenFrames(t *testing.T) {
	srcMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	gwMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 2}
	payload := []byte("golden payload")
	const ttl = 6

	tcs := []struct {
		name     string
		src, dst string
		proto    layers.IPProtocol
		md5      bool
	}{
		{
			name:  "ipv4 tcp",
			src:   "192.0.2.1",
			dst:   "203.0.113.1",
			proto: layers.IPProtocolTCP,
		},
		{
			name: "ipv4 tcp md5", src: "192.0.2.1", dst: "203.0.113.1",
			proto: layers.IPProtocolTCP, md5: true,
		},
		{
			name:  "ipv4 udp",
			src:   "192.0.2.1",
			dst:   "203.0.113.1",
			proto: layers.IPProtocolUDP,
		},
		{
			name:  "ipv6 tcp",
			src:   "2001:db8::1",
			dst:   "2001:db8::2",
			proto: layers.IPProtocolTCP,
		},
		{
			name: "ipv6 tcp md5", src: "2001:db8::1", dst: "2001:db8::2",
			proto: layers.IPProtocolTCP, md5: true,
		},
		{
			name:  "ipv6 udp",
			src:   "2001:db8::1",
			dst:   "2001:db8::2",
			proto: layers.IPProtocolUDP,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			h := &captureHandle{}
			l2 := NewL2Sender(h, srcMAC, gwMAC)
			senders := Senders{V4: l2, V6: l2}
			srcIP, dstIP := net.ParseIP(tc.src), net.ParseIP(tc.dst)
			fake := TCPFake{SeqAck: SeqAck{Seq: 1000, Ack: 5000}, BadMD5Sig: tc.md5}

			var err error
			if tc.proto == layers.IPProtocolTCP {
				_, err = NewTCPWriter(zerolog.Nop(), senders).WriteCraftedPacketWithSeq(
					context.Background(),
					&net.TCPAddr{IP: srcIP, Port: 50000},
					&net.TCPAddr{IP: dstIP, Port: 443},
					ttl, payload, fake,
				)
			} else {
				_, err = NewUDPWriter(zerolog.Nop(), senders).WriteCraftedPacket(
					context.Background(),
					&net.UDPAddr{IP: srcIP, Port: 50000},
					&net.UDPAddr{IP: dstIP, Port: 443},
					ttl, payload,
				)
			}
			require.NoError(t, err)
			require.Len(t, h.frames, 1)
			got := h.frames[0]

			want := oneShotFrame(t, srcMAC, gwMAC, srcIP, dstIP, tc.proto, fake, got, payload)
			assert.Equal(t, want, got)
		})
	}
}

// oneShotFrame builds, in one pass as the writers did before, the frame
// of a fake with ttl 6 from srcIP:50000 to dstIP:443. A TCP fake gets the
// options decoded from sent, the frame under test, so that a random MD5
// digest matches.
func oneShotFrame(
	t *testing.T,
	srcMAC, dstMAC net.HardwareAddr,
	srcIP, dstIP net.IP,
	proto layers.IPProtocol,
	fake TCPFake,
	sent, payload []byte,
) []byte {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC}
	var ip interface {
		gopacket.NetworkLayer
		gopacket.SerializableLayer
	}
	if srcIP.To4() != nil {
		eth.EthernetType = layers.EthernetTypeIPv4
		ip = &layers.IPv4{Version: 4, TTL: 6, Protocol: proto, SrcIP: srcIP, DstIP: dstIP}
	} else {
		eth.EthernetType = layers.EthernetTypeIPv6
		ip = &layers.IPv6{
			Version:    6,
			HopLimit:   6,
			NextHeader: proto,
			SrcIP:      srcIP,
			DstIP:      dstIP,
		}
	}

	var l4 transportLayer
	if proto == layers.IPProtocolTCP {
		decoded := gopacket.NewPacket(sent, layers.LayerTypeEthernet, gopacket.Default)
		sentTCP, ok := decoded.Layer(layers.LayerTypeTCP).(*layers.TCP)
		require.True(t, ok)
		l4 = &layers.TCP{
			SrcPort: 50000,
			DstPort: 443,
			Seq:     fake.Seq,
			PSH:     true,
			ACK:     true,
			Ack:     fake.Ack,
			Window:  12345,
			Options: sentTCP.Options,
		}
	} else {
		l4 = &layers.UDP{SrcPort: 50000, DstPort: 443}
	}
	require.NoError(t, l4.SetNetworkLayerForChecksum(ip))

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	require.NoError(
		t,
		gopacket.SerializeLayers(buf, opts, eth, ip, l4, gopacket.Payload(payload)),
	)
	return buf.Bytes()
}
