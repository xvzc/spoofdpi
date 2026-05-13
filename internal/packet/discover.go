package packet

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/netutil"
)

var dnsProbe = &netutil.Destination{
	Addrs: []net.IP{
		net.ParseIP("8.8.8.8"),
		net.ParseIP("8.8.4.4"),
		net.ParseIP("1.1.1.1"),
		net.ParseIP("1.0.0.1"),
		net.ParseIP("9.9.9.9"),
	},
	Port: 53,
}

// DiscoverRoute discovers the default network route by observing ARP traffic.
func DiscoverRoute(ctx context.Context, logger zerolog.Logger) (*Route, error) {
	conn, err := netutil.DialFastest(ctx, dnsProbe, "udp", 2*time.Second, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot reach external network: %w", err)
	}
	localIP := conn.LocalAddr().(*net.UDPAddr).IP
	_ = conn.Close()

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("net.Interfaces: %w", err)
	}

	iface, subnets, err := findIfaceByIP(localIP, ifaces)
	if err != nil {
		return nil, err
	}

	if len(iface.HardwareAddr) == 0 {
		if physical := findPhysicalInterface(ifaces); physical != nil {
			iface = physical
			addrs, _ := iface.Addrs()
			subnets = buildSubnets(addrs)
		}
	}

	handle, err := NewHandle(iface)
	if err != nil {
		return nil, fmt.Errorf("open handle on %s: %w", iface.Name, err)
	}
	defer handle.Close()

	gwIP, gwMAC, err := captureRouteInfo(
		ctx,
		logger,
		handle,
		localIP,
		iface.HardwareAddr,
		subnets,
	)
	if err != nil {
		return nil, err
	}

	return &Route{
		Iface:      *iface,
		Gateway:    gwIP,
		GatewayMAC: gwMAC,
	}, nil
}

type subnetAddr struct {
	ip      net.IP
	netmask net.IPMask
}

func buildSubnets(addrs []net.Addr) []subnetAddr {
	var subnets []subnetAddr
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			subnets = append(subnets, subnetAddr{ip: ipnet.IP, netmask: ipnet.Mask})
		}
	}
	return subnets
}

func findIfaceByIP(
	localIP net.IP,
	ifaces []net.Interface,
) (*net.Interface, []subnetAddr, error) {
	for i := range ifaces {
		iface := ifaces[i]
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.Equal(localIP) {
				return &iface, buildSubnets(addrs), nil
			}
		}
	}
	return nil, nil, fmt.Errorf("no interface found for %s", localIP)
}

func findPhysicalInterface(ifaces []net.Interface) *net.Interface {
	for i := range ifaces {
		iface := ifaces[i]
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if len(iface.HardwareAddr) == 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil &&
				!ipnet.IP.IsLoopback() {
				return &iface
			}
		}
	}
	return nil
}

type routeCapture struct {
	mu    sync.Mutex
	gwIP  net.IP
	gwMAC net.HardwareAddr
}

func (c *routeCapture) update(pkt gopacket.Packet, localIP net.IP) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if arpLayer := pkt.Layer(layers.LayerTypeARP); arpLayer != nil {
		arp := arpLayer.(*layers.ARP)
		srcProto := net.IP(arp.SourceProtAddress)
		dstProto := net.IP(arp.DstProtAddress)

		if srcProto.Equal(localIP) {
			if arp.Operation == layers.ARPRequest && c.gwIP == nil &&
				!dstProto.Equal(localIP) {
				c.gwIP = cloneIP(dstProto)
			}
		}
		if arp.Operation == layers.ARPReply && dstProto.Equal(localIP) {
			if c.gwMAC == nil {
				c.gwMAC = cloneMAC(arp.SourceHwAddress)
			}
			if c.gwIP == nil {
				c.gwIP = cloneIP(srcProto)
			}
		}
		return
	}

	ethLayer := pkt.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return
	}
	eth := ethLayer.(*layers.Ethernet)

	var srcIP, dstIP net.IP
	if ipLayer := pkt.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip := ipLayer.(*layers.IPv4)
		srcIP, dstIP = ip.SrcIP, ip.DstIP
	} else if ipLayer := pkt.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip := ipLayer.(*layers.IPv6)
		srcIP, dstIP = ip.SrcIP, ip.DstIP
	}

	if srcIP.Equal(localIP) && !isPrivateIP(dstIP) {
		if c.gwMAC == nil {
			c.gwMAC = cloneMAC(eth.DstMAC)
		}
	}
}

func (c *routeCapture) isComplete() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.gwIP != nil && len(c.gwMAC) > 0
}

func (c *routeCapture) snapshot() (gwIP net.IP, gwMAC net.HardwareAddr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.gwIP, c.gwMAC
}

func captureRouteInfo(
	ctx context.Context,
	_ zerolog.Logger,
	handle Handle,
	localIP net.IP,
	ifaceMAC net.HardwareAddr,
	subnets []subnetAddr,
) (net.IP, net.HardwareAddr, error) {
	state := &routeCapture{}

	go func() {
		src := gopacket.NewPacketSource(handle, handle.LinkType())
		for {
			select {
			case <-ctx.Done():
				return
			case pkt, ok := <-src.Packets():
				if !ok {
					return
				}
				state.update(pkt, localIP)
			}
		}
	}()

	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case <-time.After(200 * time.Millisecond):
	}

	probeGateway(ctx)

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	arpProbed := false

	for {
		if state.isComplete() {
			gwIP, gwMAC := state.snapshot()
			return gwIP, gwMAC, nil
		}
		select {
		case <-ctx.Done():
			return nil, nil, fmt.Errorf("route discovery timed out")
		case <-ticker.C:
			probeGateway(ctx)
			gwIP, _ := state.snapshot()
			if gwIP == nil && !arpProbed {
				sendGatewayARPProbes(handle, ifaceMAC, localIP, subnets)
				arpProbed = true
			}
		}
	}
}

func sendGatewayARPProbes(
	handle Handle,
	ifaceMAC net.HardwareAddr,
	localIP net.IP,
	subnets []subnetAddr,
) {
	localIP4 := localIP.To4()
	if localIP4 == nil {
		return
	}
	for _, s := range subnets {
		subnet := s.ip.Mask(s.netmask)
		if len(subnet) < 4 {
			continue
		}
		for _, offset := range []byte{1, 2, 254} {
			probeIP := net.IP{subnet[0], subnet[1], subnet[2], offset}
			if probeIP.Equal(localIP4) {
				continue
			}
			_ = sendARPRequest(handle, ifaceMAC, localIP4, probeIP)
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

func cloneIP(ip net.IP) net.IP {
	out := make(net.IP, len(ip))
	copy(out, ip)
	return out
}

func isPrivateIP(ip net.IP) bool {
	return ip.IsPrivate() ||
		ip.IsLoopback() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsLinkLocalUnicast()
}

func cloneMAC(mac net.HardwareAddr) net.HardwareAddr {
	out := make(net.HardwareAddr, len(mac))
	copy(out, mac)
	return out
}

func probeGateway(ctx context.Context) {
	conn, err := netutil.DialFastest(ctx, dnsProbe, "udp", 2*time.Second, nil)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()

	_, _ = conn.Write([]byte("."))
}
