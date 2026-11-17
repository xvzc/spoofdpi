package packet

import (
	"context"
	"errors"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog"
)

var _ Writer = (*UDPWriter)(nil)

type UDPWriter struct {
	logger zerolog.Logger

	handle     Handle
	iface      *net.Interface
	gatewayMAC net.HardwareAddr
}

func NewUDPWriter(
	logger zerolog.Logger,
	handle Handle,
	iface *net.Interface,
	gatewayMAC net.HardwareAddr,
) *UDPWriter {
	return &UDPWriter{
		logger:     logger,
		handle:     handle,
		iface:      iface,
		gatewayMAC: gatewayMAC,
	}
}

// --- Injector Methods ---

// WriteCraftedPacket crafts and injects a full UDP packet from a payload.
// It uses the pre-configured gateway MAC address.
func (uw *UDPWriter) WriteCraftedPacket(
	ctx context.Context,
	src net.Addr,
	dst net.Addr,
	ttl uint8,
	payload []byte,
) (int, error) {
	// set variables for src/dst
	srcMAC := uw.iface.HardwareAddr
	dstMAC := uw.gatewayMAC

	srcUDP, ok := src.(*net.UDPAddr)
	if !ok {
		return 0, errors.New("src is not *net.UDPAddr")
	}

	dstUDP, ok := dst.(*net.UDPAddr)
	if !ok {
		return 0, errors.New("dst is not *net.UDPAddr")
	}

	srcPort := srcUDP.Port
	dstPort := dstUDP.Port

	var err error
	var packetLayers []gopacket.SerializableLayer
	if dstUDP.IP.To4() != nil {
		packetLayers, err = uw.createIPv4Layers(
			srcMAC,
			dstMAC,
			srcUDP.IP,
			dstUDP.IP,
			srcPort,
			dstPort,
			ttl,
		)
	} else {
		packetLayers, err = uw.createIPv6Layers(
			srcMAC,
			dstMAC,
			srcUDP.IP,
			dstUDP.IP,
			srcPort,
			dstPort,
			ttl,
		)
	}

	if err != nil {
		return 0, err
	}

	// serialize the packet L2(optional) + L3 + L4 + payload
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true, // Recalculate checksums
		FixLengths:       true, // Fix lengths
	}

	packetLayers = append(packetLayers, gopacket.Payload(payload))

	err = gopacket.SerializeLayers(buf, opts, packetLayers...)
	if err != nil {
		return 0, err
	}

	// inject the raw L2 packet
	if err := uw.handle.WritePacketData(buf.Bytes()); err != nil {
		return 0, err
	}

	return len(payload), nil
}

func (uw *UDPWriter) createIPv4Layers(
	srcMAC net.HardwareAddr,
	dstMAC net.HardwareAddr,
	srcIP net.IP,
	dstIP net.IP,
	srcPort int,
	dstPort int,
	ttl uint8,
) ([]gopacket.SerializableLayer, error) {
	var packetLayers []gopacket.SerializableLayer

	if srcMAC != nil && dstMAC != nil {
		eth := &layers.Ethernet{
			SrcMAC:       srcMAC,
			DstMAC:       dstMAC,
			EthernetType: layers.EthernetTypeIPv4,
		}
		packetLayers = append(packetLayers, eth)
	}

	// define ip layer
	ipLayer := &layers.IPv4{
		Version:  4,
		TTL:      ttl,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}
	packetLayers = append(packetLayers, ipLayer)

	// define udp layer
	udpLayer := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	packetLayers = append(packetLayers, udpLayer)

	if err := udpLayer.SetNetworkLayerForChecksum(ipLayer); err != nil {
		return nil, err
	}

	return packetLayers, nil
}

func (uw *UDPWriter) createIPv6Layers(
	srcMAC net.HardwareAddr,
	dstMAC net.HardwareAddr,
	srcIP net.IP,
	dstIP net.IP,
	srcPort int,
	dstPort int,
	ttl uint8,
) ([]gopacket.SerializableLayer, error) {
	var packetLayers []gopacket.SerializableLayer

	if srcMAC != nil && dstMAC != nil {
		eth := &layers.Ethernet{
			SrcMAC:       srcMAC,
			DstMAC:       dstMAC,
			EthernetType: layers.EthernetTypeIPv6,
		}
		packetLayers = append(packetLayers, eth)
	}

	ipLayer := &layers.IPv6{
		Version:    6,
		HopLimit:   ttl,
		NextHeader: layers.IPProtocolUDP,
		SrcIP:      srcIP,
		DstIP:      dstIP,
	}
	packetLayers = append(packetLayers, ipLayer)

	udpLayer := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	packetLayers = append(packetLayers, udpLayer)

	if err := udpLayer.SetNetworkLayerForChecksum(ipLayer); err != nil {
		return nil, err
	}

	return packetLayers, nil
}
