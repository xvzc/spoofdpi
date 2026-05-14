package packet

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	gw "github.com/jackpal/gateway"
	"github.com/xvzc/spoofdpi/internal/config"
)

// DiscoverRoute discovers the default network route.
// Gateway IP and interface are resolved from the OS routing table.
// GatewayMAC is resolved via ARP only when cfg.NeedsPcap() is true.
func DiscoverRoute(ctx context.Context, cfg *config.Config) (*Route, error) {
	gwIP, err := gw.DiscoverGateway()
	if err != nil {
		return nil, fmt.Errorf("discover gateway: %w", err)
	}

	localIP, err := gw.DiscoverInterface()
	if err != nil {
		return nil, fmt.Errorf("discover interface: %w", err)
	}

	iface, err := findIfaceByIP(localIP)
	if err != nil {
		return nil, err
	}

	route := &Route{
		Iface:   *iface,
		Gateway: gwIP,
	}

	if cfg.NeedsPcap() {
		route.GatewayMAC, err = resolveGatewayMAC(ctx, iface, localIP, gwIP)
		if err != nil {
			return nil, err
		}
	}

	return route, nil
}

func findIfaceByIP(localIP net.IP) (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("net.Interfaces: %w", err)
	}
	for i := range ifaces {
		iface := &ifaces[i]
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.Equal(localIP) {
				return iface, nil
			}
		}
	}
	return nil, fmt.Errorf("no interface found for %s", localIP)
}

func resolveGatewayMAC(
	ctx context.Context,
	iface *net.Interface,
	localIP, gwIP net.IP,
) (net.HardwareAddr, error) {
	localIP4 := localIP.To4()
	gwIP4 := gwIP.To4()
	if localIP4 == nil || gwIP4 == nil {
		return nil, fmt.Errorf("non-IPv4 gateway not supported")
	}

	handle, err := NewHandle(iface)
	if err != nil {
		return nil, fmt.Errorf("open pcap handle on %s: %w", iface.Name, err)
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
	handle Handle,
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

func sendARPRequest(handle Handle, srcMAC net.HardwareAddr, srcIP, dstIP net.IP) error {
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
