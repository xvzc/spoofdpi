package packet

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/xvzc/spoofdpi/internal/capture"
	"github.com/xvzc/spoofdpi/internal/inject"
)

var _ inject.Sender = (*L2Sender)(nil)

// L2Sender is an inject.Sender that writes each packet as a link-layer
// frame to a capture handle, bypassing the kernel's IP layer. The frame is
// an Ethernet frame from srcMAC to dstMAC, the gateway's, or a bare IP
// packet when either MAC is nil. The IP header has no options, no DF, and
// an ID of 0.
type L2Sender struct {
	handle         capture.Handle
	srcMAC, dstMAC net.HardwareAddr
}

// NewL2Sender returns an L2Sender that writes to handle and owns it.
func NewL2Sender(handle capture.Handle, srcMAC, dstMAC net.HardwareAddr) *L2Sender {
	return &L2Sender{handle: handle, srcMAC: srcMAC, dstMAC: dstMAC}
}

// OpenL2Sender opens a capture handle on iface that is only written to,
// and returns an L2Sender that sends Ethernet frames from iface to
// gatewayMAC through it.
func OpenL2Sender(
	iface *net.Interface,
	gatewayMAC net.HardwareAddr,
) (*L2Sender, error) {
	handle, err := openWriteHandle(iface)
	if err != nil {
		return nil, err
	}
	return NewL2Sender(handle, iface.HardwareAddr, gatewayMAC), nil
}

// Send writes p as one frame. A failure is an *inject.SendError.
func (s *L2Sender) Send(p inject.Packet) error {
	frame, err := s.frame(p)
	if err != nil {
		return inject.NewSendError(p.Dst, err)
	}
	if err := s.handle.WritePacketData(frame); err != nil {
		return inject.NewSendError(p.Dst, err)
	}
	return nil
}

// Close closes the handle.
func (s *L2Sender) Close() error {
	s.handle.Close()
	return nil
}

// frame returns p as the frame that Send writes.
func (s *L2Sender) frame(p inject.Packet) ([]byte, error) {
	var frameLayers []gopacket.SerializableLayer
	ethType := layers.EthernetTypeIPv4
	if p.Dst.Is6() {
		ethType = layers.EthernetTypeIPv6
	}
	if s.srcMAC != nil && s.dstMAC != nil {
		frameLayers = append(frameLayers, &layers.Ethernet{
			SrcMAC:       s.srcMAC,
			DstMAC:       s.dstMAC,
			EthernetType: ethType,
		})
	}

	proto := layers.IPProtocol(p.Proto)
	if p.Dst.Is4() {
		frameLayers = append(frameLayers, &layers.IPv4{
			Version:  4,
			TTL:      p.HopLimit,
			Protocol: proto,
			SrcIP:    p.Src.AsSlice(),
			DstIP:    p.Dst.AsSlice(),
		})
	} else {
		frameLayers = append(frameLayers, &layers.IPv6{
			Version:    6,
			HopLimit:   p.HopLimit,
			NextHeader: proto,
			SrcIP:      p.Src.AsSlice(),
			DstIP:      p.Dst.AsSlice(),
		})
	}
	// The transport segment goes as it is: its checksum is already set.
	frameLayers = append(frameLayers, gopacket.Payload(p.L4))

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, frameLayers...); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
