package netutil

import (
	"fmt"
	"net"

	gw "github.com/jackpal/gateway"
)

// Route represents the default network route.
type Route struct {
	Iface   net.Interface
	LocalIP net.IP
	Gateway net.IP
}

// DiscoverInterface discovers the interface of the default route and its
// local IP from the OS. It does not require a gateway.
func DiscoverInterface() (*net.Interface, net.IP, error) {
	localIP, err := gw.DiscoverInterface()
	if err != nil {
		return nil, nil, fmt.Errorf("discover interface: %w", err)
	}

	iface, err := findIfaceByIP(localIP)
	if err != nil {
		return nil, nil, err
	}

	return iface, localIP, nil
}

// DiscoverRoute discovers the default network route.
// Gateway IP and interface are resolved from the OS routing table.
func DiscoverRoute() (*Route, error) {
	gwIP, err := gw.DiscoverGateway()
	if err != nil {
		return nil, fmt.Errorf("discover gateway: %w", err)
	}

	iface, localIP, err := DiscoverInterface()
	if err != nil {
		return nil, err
	}

	return &Route{
		Iface:   *iface,
		LocalIP: localIP,
		Gateway: gwIP,
	}, nil
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
