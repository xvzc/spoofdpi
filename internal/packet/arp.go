package packet

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/netutil"
)

var dnsServers = []net.IP{
	net.ParseIP("8.8.8.8"),
	net.ParseIP("8.8.4.4"),
	net.ParseIP("1.1.1.1"),
	net.ParseIP("1.0.0.1"),
	net.ParseIP("9.9.9.9"),
}

// ResolveGatewayMAC determines the upstream gateway's MAC address by
// passively observing outbound traffic on iface. It opens a pcap handle,
// triggers traffic via short DNS probes, and returns the first MAC seen
// for non-private destinations.
func ResolveGatewayMAC(
	ctx context.Context,
	logger zerolog.Logger,
	iface *net.Interface,
) (net.HardwareAddr, error) {
	if len(iface.HardwareAddr) == 0 {
		return nil, fmt.Errorf("interface %s has no MAC address", iface.Name)
	}

	handle, err := NewHandle(iface)
	if err != nil {
		return nil, fmt.Errorf("open pcap handle on %s: %w", iface.Name, err)
	}
	defer handle.Close()

	macCh := make(chan net.HardwareAddr, 1)
	go captureGatewayMAC(ctx, handle, iface, macCh)

	// Let the capture goroutine start before generating traffic.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(300 * time.Millisecond):
	}

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	probeGateway(ctx)

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("resolve gateway MAC: %w", ctx.Err())
		case mac := <-macCh:
			return mac, nil
		case <-ticker.C:
			probeGateway(ctx)
		}
	}
}

func captureGatewayMAC(
	ctx context.Context,
	handle Handle,
	iface *net.Interface,
	macCh chan<- net.HardwareAddr,
) {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case <-ctx.Done():
			return
		case p, ok := <-packetSource.Packets():
			if !ok {
				return
			}
			if mac := extractGatewayMAC(p, iface.HardwareAddr); mac != nil {
				select {
				case macCh <- mac:
				case <-ctx.Done():
				}
				return
			}
		}
	}
}

func extractGatewayMAC(p gopacket.Packet, ifaceMAC net.HardwareAddr) net.HardwareAddr {
	var srcIP, dstIP net.IP
	if ipLayer := p.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip := ipLayer.(*layers.IPv4)
		srcIP, dstIP = ip.SrcIP, ip.DstIP
	} else if ipLayer := p.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip := ipLayer.(*layers.IPv6)
		srcIP, dstIP = ip.SrcIP, ip.DstIP
	}

	ethLayer := p.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return nil
	}
	eth := ethLayer.(*layers.Ethernet)

	// Outbound: traffic from us to a non-private destination → DstMAC is the gateway.
	if eth.SrcMAC.String() == ifaceMAC.String() && dstIP != nil && !isPrivateIP(dstIP) {
		return cloneMAC(eth.DstMAC)
	}

	// Inbound: traffic from a non-private source to us → SrcMAC is the gateway.
	if eth.DstMAC.String() == ifaceMAC.String() && srcIP != nil && !isPrivateIP(srcIP) {
		return cloneMAC(eth.SrcMAC)
	}

	return nil
}

func cloneMAC(mac net.HardwareAddr) net.HardwareAddr {
	out := make(net.HardwareAddr, len(mac))
	copy(out, mac)
	return out
}

func isPrivateIP(ip net.IP) bool {
	return ip.IsPrivate() ||
		ip.IsLoopback() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsLinkLocalUnicast()
}

func probeGateway(ctx context.Context) {
	conn, err := netutil.DialFastest(ctx, &netutil.Destination{
		Addrs: dnsServers,
		Port:  53,
	}, "udp", 2*time.Second, nil)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()

	_, _ = conn.Write([]byte("."))
}
