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

var dnsServers = []net.IP{
	net.ParseIP("8.8.8.8"),
	net.ParseIP("8.8.4.4"),
	net.ParseIP("1.1.1.1"),
	net.ParseIP("1.0.0.1"),
	net.ParseIP("9.9.9.9"),
}

type NetworkDetector struct {
	logger zerolog.Logger
	handle Handle
	iface  *net.Interface

	clientIP   net.IP
	gatewayMAC net.HardwareAddr
	mu         sync.RWMutex
	found      chan struct{}
}

func NewNetworkDetector(
	logger zerolog.Logger,
) *NetworkDetector {
	return &NetworkDetector{
		logger: logger,
		found:  make(chan struct{}),
	}
}

func (nd *NetworkDetector) Start(ctx context.Context) error {
	iface, err := findDefaultInterface(ctx)
	if err != nil {
		return err
	}
	nd.iface = iface

	handle, err := NewHandle(iface)
	if err != nil {
		return err
	}
	nd.handle = handle

	go func() {
		defer nd.handle.Close()

		packetSource := gopacket.NewPacketSource(nd.handle, nd.handle.LinkType())

		for {
			select {
			case <-ctx.Done():
				return
			case p := <-packetSource.Packets():
				nd.processPacket(p)
			}
		}
	}()

	go func() {
		// Wait for the packet capture to start
		select {
		case <-ctx.Done():
			return
		case <-time.After(300 * time.Millisecond):
		}

		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()

		nd.probe(ctx)

		for {
			select {
			case <-ctx.Done():
				return
			case <-nd.found:
				return
			case <-ticker.C:
				nd.probe(ctx)
			}
		}
	}()

	return nil
}

func (nd *NetworkDetector) probe(ctx context.Context) {
	conn, err := netutil.DialFastest(ctx, "udp", &netutil.Destination{
		Addrs: dnsServers,
		Port:  53,
	}, 2*time.Second, nil)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()

	_, _ = conn.Write([]byte("."))
}

func (nd *NetworkDetector) processPacket(p gopacket.Packet) {
	nd.mu.RLock()
	found := nd.gatewayMAC != nil && nd.clientIP != nil
	nd.mu.RUnlock()
	if found {
		return
	}

	var srcIP net.IP
	var dstIP net.IP

	if ipLayer := p.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip := ipLayer.(*layers.IPv4)
		srcIP = ip.SrcIP
		dstIP = ip.DstIP
	} else if ipLayer := p.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip := ipLayer.(*layers.IPv6)
		srcIP = ip.SrcIP
		dstIP = ip.DstIP
	}

	ethLayer := p.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return
	}
	eth := ethLayer.(*layers.Ethernet)

	// Case 1: Outbound Packet (From Me)
	if eth.SrcMAC.String() == nd.iface.HardwareAddr.String() {
		// Identify Client IP (Me)
		if srcIP != nil {
			nd.setClientIP(srcIP)
		}

		// Identify Gateway MAC (To Internet)
		// Assuming traffic to non-local IP goes to Gateway.
		if dstIP != nil && !nd.isPrivateIP(dstIP) {
			nd.setGatewayMAC(eth.DstMAC)
		}
		return
	}

	// Case 2: Inbound Packet (To Me)
	if eth.DstMAC.String() == nd.iface.HardwareAddr.String() {
		// Identify Client IP (Me)
		if dstIP != nil {
			nd.setClientIP(dstIP)
		}

		// Identify Gateway MAC (From Internet)
		// Assuming traffic from non-local IP comes from Gateway.
		if srcIP != nil && !nd.isPrivateIP(srcIP) {
			nd.setGatewayMAC(eth.SrcMAC)
		}
		return
	}
}

func (nd *NetworkDetector) isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast() {
		return true
	}

	if ip4 := ip.To4(); ip4 != nil {
		switch ip4[0] {
		case 10:
			return true
		case 172:
			return ip4[1] >= 16 && ip4[1] <= 31
		case 192:
			return ip4[1] == 168
		}
		return false
	}
	return false // IPv6 public check is more complex, assuming public for now if not link-local
}

func (nd *NetworkDetector) setClientIP(ip net.IP) {
	nd.mu.Lock()
	defer nd.mu.Unlock()

	if nd.clientIP == nil {
		nd.clientIP = make(net.IP, len(ip))
		copy(nd.clientIP, ip)
		nd.checkFound()
	}
}

func (nd *NetworkDetector) setGatewayMAC(mac net.HardwareAddr) {
	nd.mu.Lock()
	defer nd.mu.Unlock()

	if nd.gatewayMAC == nil {
		nd.gatewayMAC = make(net.HardwareAddr, len(mac))
		copy(nd.gatewayMAC, mac)
		nd.checkFound()
	}
}

func (nd *NetworkDetector) checkFound() {
	if nd.gatewayMAC != nil && nd.clientIP != nil {
		select {
		case <-nd.found:
		default:
			close(nd.found)
		}
	}
}

func (nd *NetworkDetector) IsFound() bool {
	nd.mu.RLock()
	defer nd.mu.RUnlock()
	return nd.gatewayMAC != nil && nd.clientIP != nil
}

func (nd *NetworkDetector) GetGatewayMAC() net.HardwareAddr {
	nd.mu.RLock()
	defer nd.mu.RUnlock()
	return nd.gatewayMAC
}

// WaitForGatewayMAC blocks until the passive detector has observed the
// upstream gateway's MAC address (or until ctx is cancelled). It does
// not return the MAC — callers read it back via GetGatewayMAC() once
// this returns. A nil MAC after wait means detection didn't complete
// in time.
func (nd *NetworkDetector) WaitForGatewayMAC(ctx context.Context) {
	if nd.iface.HardwareAddr == nil {
		return
	}
	if nd.IsFound() {
		return
	}
	select {
	case <-nd.found:
	case <-ctx.Done():
	}
}

func (nd *NetworkDetector) GetInterface() *net.Interface {
	return nd.iface
}

func findDefaultInterface(ctx context.Context) (*net.Interface, error) {
	conn, err := netutil.DialFastest(
		ctx,
		"udp",
		&netutil.Destination{
			Addrs: dnsServers,
			Port:  53,
		},
		20*time.Second,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"could not dial any public DNS to determine default interface: %w",
			err,
		)
	}
	defer func() { _ = conn.Close() }()

	// Check the local IP address used for the connection
	localAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil, fmt.Errorf(
			"could not determine local address from UDP connection",
		)
	}

	// Search for the network interface (iface) that has this local IP
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf(
			"could not get network interfaces: %w",
			err,
		)
	}

	var defaultIface *net.Interface

	for i := range ifaces {
		iface := ifaces[i]
		addrs, err := iface.Addrs()
		if err != nil {
			continue // Skip interfaces whose addresses cannot be retrieved
		}
		for _, addr := range addrs {
			// Check if it is of type net.IPNet
			if ipnet, ok := addr.(*net.IPNet); ok {
				// Check if the IP used for Dial matches the interface's IP
				if ipnet.IP.Equal(localAddr.IP) {
					if len(iface.HardwareAddr) > 0 {
						return &iface, nil // Found the default interface with MAC
					}
					defaultIface = &iface
				}
			}
		}
	}

	// fmt.Println("hello")

	// If we found a default interface but it has no MAC (e.g. VPN/TUN),
	// try to find a physical interface as fallback.
	if defaultIface != nil {
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
				if ipnet, ok := addr.(*net.IPNet); ok {
					if ipnet.IP.To4() != nil && !ipnet.IP.IsLoopback() {
						return &iface, nil
					}
				}
			}
		}
		return defaultIface, nil
	}

	return nil, fmt.Errorf(
		"failed to find default interface for local IP: %s",
		localAddr.IP,
	)
}
