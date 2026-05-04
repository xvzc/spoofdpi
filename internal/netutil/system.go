package netutil

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/http"

	"github.com/jackpal/gateway"
)

// Route represents a network route with interface and gateway.
// GatewayMAC is optional and only populated when raw L2 packet
// emission is needed (e.g., TUN mode, fake-packet desync).
type Route struct {
	Iface      net.Interface
	Gateway    net.IP
	GatewayMAC net.HardwareAddr
}

// DiscoverDefaultRoute probes the local system for the default network
// route (interface + gateway). If the matched interface has no MAC
// address (e.g., a VPN/TUN is the default route), it falls back to a
// physical interface so callers that need raw L2 emission still get a
// usable NIC.
func DiscoverDefaultRoute() (*Route, error) {
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var defaultIface net.Interface
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ipnet.IP.Equal(localAddr.IP) {
					defaultIface = iface
					break
				}
			}
		}
		if defaultIface.Name != "" {
			break
		}
	}

	if defaultIface.Name == "" {
		return nil, fmt.Errorf("default interface not found")
	}

	if len(defaultIface.HardwareAddr) == 0 {
		if physical := findPhysicalInterface(ifaces); physical != nil {
			defaultIface = *physical
		}
	}

	gatewayIp, err := gateway.DiscoverGateway()
	if err != nil {
		return nil, fmt.Errorf("failed to get default gateway: %w", err)
	}

	return &Route{Iface: defaultIface, Gateway: gatewayIp}, nil
}

// findPhysicalInterface returns the first up, non-loopback interface
// with a hardware address and a non-loopback IPv4 address. Returns nil
// when no such interface exists.
func findPhysicalInterface(ifaces []net.Interface) *net.Interface {
	for i := range ifaces {
		iface := ifaces[i]
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if len(iface.HardwareAddr) == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if ipnet.IP.To4() != nil && !ipnet.IP.IsLoopback() {
				return &iface
			}
		}
	}
	return nil
}

func FindSafeCIDR() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}

	var existingNets []*net.IPNet
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			existingNets = append(existingNets, ipnet)
		}
	}

	for i := 0; i < 256; i++ {
		for j := 0; j < 256; j++ {
			local := net.IPv4(10, byte(i), byte(j), 1)
			remote := net.IPv4(10, byte(i), byte(j), 2)

			conflict := false
			for _, ipnet := range existingNets {
				if ipnet.Contains(local) || ipnet.Contains(remote) {
					conflict = true
					break
				}
			}

			if !conflict {
				return fmt.Sprintf("10.%d.%d.0/30", i, j), nil
			}
		}
	}

	return "", fmt.Errorf("failed to find an available address in 10.0.0.0/8")
}

func AddrInCIDR(cidr string, n int) (string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", err
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return "", fmt.Errorf("not an IPv4 CIDR")
	}

	ipInt := binary.BigEndian.Uint32(ip4)

	resultInt := ipInt + uint32(n)

	resultIP := make(net.IP, 4)
	binary.BigEndian.PutUint32(resultIP, resultInt)

	if !ipnet.Contains(resultIP) {
		return "", fmt.Errorf("index %d is out of CIDR range %s", n, cidr)
	}

	return resultIP.String(), nil
}

func RunPACServer(content string) (string, *http.Server, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(content))
	})

	server := &http.Server{
		Handler: mux,
	}

	go func() {
		_ = server.Serve(listener)
	}()

	addr := listener.Addr().(*net.TCPAddr)
	url := fmt.Sprintf("http://127.0.0.1:%d/proxy.pac", addr.Port)

	return url, server, nil
}
