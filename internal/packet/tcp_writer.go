package packet

import (
	"context"
	"errors"
	"math/rand/v2"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog"
)

var _ Writer = (*TCPWriter)(nil)

type TCPWriter struct {
	logger zerolog.Logger

	handle     Handle
	iface      *net.Interface
	gatewayMAC net.HardwareAddr
}

func NewTCPWriter(
	logger zerolog.Logger,
	handle Handle,
	iface *net.Interface,
	gatewayMAC net.HardwareAddr,
) *TCPWriter {
	return &TCPWriter{
		logger:     logger,
		handle:     handle,
		iface:      iface,
		gatewayMAC: gatewayMAC,
	}
}

// --- Injector Methods ---

// WriteCraftedPacket crafts and injects a full TCP packet from a payload.
// It uses the pre-configured gateway MAC address.
func (tw *TCPWriter) WriteCraftedPacket(
	ctx context.Context,
	src net.Addr,
	dst net.Addr,
	ttl uint8,
	payload []byte,
) (int, error) {
	// set variables for src/dst
	srcMAC := tw.iface.HardwareAddr
	dstMAC := tw.gatewayMAC

	srcTCP, ok := src.(*net.TCPAddr)
	if !ok {
		return 0, errors.New("src is not *net.TCPAddr")
	}

	dstTCP, ok := dst.(*net.TCPAddr)
	if !ok {
		return 0, errors.New("dst is not *net.TCPAddr")
	}

	srcPort := srcTCP.Port
	dstPort := dstTCP.Port

	var err error
	var packetLayers []gopacket.SerializableLayer
	if dstTCP.IP.To4() != nil {
		packetLayers, err = tw.createIPv4Layers(
			srcMAC,
			dstMAC,
			srcTCP.IP,
			dstTCP.IP,
			srcPort,
			dstPort,
			ttl,
		)
	} else {
		packetLayers, err = tw.createIPv6Layers(
			srcMAC,
			dstMAC,
			srcTCP.IP,
			srcTCP.IP,
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
	if err := tw.handle.WritePacketData(buf.Bytes()); err != nil {
		return 0, err
	}

	return len(payload), nil
}

func (tw *TCPWriter) createIPv4Layers(
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
		Protocol: layers.IPProtocolTCP,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}
	packetLayers = append(packetLayers, ipLayer)

	// define tcp layer
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort), // Use a random high port
		DstPort: layers.TCPPort(dstPort),
		Seq:     rand.Uint32(), // A random sequence number
		PSH:     true,          // Push the payload
		ACK:     true,          // Assuming this is part of an established flow
		Ack:     rand.Uint32(),
		Window:  12345,
	}
	packetLayers = append(packetLayers, tcpLayer)

	if err := tcpLayer.SetNetworkLayerForChecksum(ipLayer); err != nil {
		return nil, err
	}

	return packetLayers, nil
}

func (tw *TCPWriter) createIPv6Layers(
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
		NextHeader: layers.IPProtocolTCP,
		SrcIP:      srcIP,
		DstIP:      dstIP,
	}
	packetLayers = append(packetLayers, ipLayer)

	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     rand.Uint32(),
		PSH:     true,
		ACK:     true,
		Ack:     rand.Uint32(),
		Window:  12345,
	}
	packetLayers = append(packetLayers, tcpLayer)

	if err := tcpLayer.SetNetworkLayerForChecksum(ipLayer); err != nil {
		return nil, err
	}

	return packetLayers, nil
}
