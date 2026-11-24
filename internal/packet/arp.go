package packet

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/xvzc/spoofdpi/internal/capture"
)

// ResolveGatewayMAC resolves the MAC address of gwIP via ARP on iface.
// It opens a temporary pcap handle that is closed before returning.
func ResolveGatewayMAC(
	ctx context.Context,
	iface *net.Interface,
	localIP, gwIP net.IP,
) (net.HardwareAddr, error) {
	localIP4 := localIP.To4()
	gwIP4 := gwIP.To4()
	if localIP4 == nil || gwIP4 == nil {
		return nil, fmt.Errorf("non-IPv4 gateway not supported")
	}

	handle, err := capture.NewHandle(iface)
	if err != nil {
		return nil, fmt.Errorf("open pcap handle: %w", err)
	}
	defer handle.Close()

	macCh := make(chan net.HardwareAddr, 1)
	go captureARPReply(ctx, handle, gwIP4, macCh)

	// Let the capture goroutine start before sending the first probe.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(100 * time.Millisecond):
	}

	_ = sendARPRequest(handle, iface.HardwareAddr, localIP4, gwIP4)

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case mac := <-macCh:
			return mac, nil
		case <-ctx.Done():
			return nil, fmt.Errorf("resolve gateway MAC: timed out")
		case <-ticker.C:
			_ = sendARPRequest(handle, iface.HardwareAddr, localIP4, gwIP4)
		}
	}
}

func captureARPReply(
	ctx context.Context,
	handle capture.Handle,
	gwIP net.IP,
	macCh chan<- net.HardwareAddr,
) {
	src := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case <-ctx.Done():
			return
		case pkt, ok := <-src.Packets():
			if !ok {
				return
			}
			arpLayer := pkt.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arp := arpLayer.(*layers.ARP)
			if arp.Operation != layers.ARPReply {
				continue
			}
			if net.IP(arp.SourceProtAddress).Equal(gwIP) {
				select {
				case macCh <- cloneMAC(arp.SourceHwAddress):
				default:
				}
				return
			}
		}
	}
}

func sendARPRequest(
	handle capture.Handle,
	srcMAC net.HardwareAddr,
	srcIP, dstIP net.IP,
) error {
	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   srcMAC,
		SourceProtAddress: srcIP.To4(),
		DstHwAddress:      net.HardwareAddr{0, 0, 0, 0, 0, 0},
		DstProtAddress:    dstIP.To4(),
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &arp); err != nil {
		return err
	}
	return handle.WritePacketData(buf.Bytes())
}

func cloneMAC(mac net.HardwareAddr) net.HardwareAddr {
	out := make(net.HardwareAddr, len(mac))
	copy(out, mac)
	return out
}
