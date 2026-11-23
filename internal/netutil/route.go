package netutil

import (
	"errors"
	"fmt"
	"net"

	gw "github.com/jackpal/gateway"
)

// ErrNoIPv4Route is returned, wrapped, by DiscoverRoute when the OS has no
// IPv4 default route, for example on an IPv6-only network, and by RouteTo
// when the kernel has no route to an IPv4 destination.
var ErrNoIPv4Route = errors.New("no IPv4 default route")

// discoverGateway returns the gateway of the IPv4 default route. Tests
// replace it to fake the routing table.
var discoverGateway = gw.DiscoverGateway

// Route represents the default network route of one address family.
type Route struct {
	Family Family
	Iface  net.Interface
	// LocalIP is the address of Iface on the route, or nil when it is not
	// known. DiscoverRoute sets it only for IPv4.
	LocalIP net.IP
	// Gateway is nil for an interface route, which has no gateway.
	Gateway net.IP
	// Zone is the zone of Gateway, Iface's name, when Gateway is an IPv6
	// link-local address, and empty otherwise.
	Zone string
}

// Routes holds the default route of each address family. Either is nil
// when it was not discovered.
type Routes struct {
	V4 *Route
	V6 *Route
}

// GatewayString returns the gateway address with its zone, if any, such
// as "192.168.1.1" or "fe80::1%en0".
func (r *Route) GatewayString() string {
	if r.Zone == "" {
		return r.Gateway.String()
	}
	return r.Gateway.String() + "%" + r.Zone
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
// If gateway is nil, the gateway IP and interface are resolved from the OS
// routing table. Otherwise the given gateway is used as is, and the
// interface is the one whose subnet contains it, so the two always match.
func DiscoverRoute(gateway net.IP) (*Route, error) {
	if gateway != nil {
		return routeForGateway(gateway)
	}

	gwIP, err := discoverGateway()
	if err != nil {
		return nil, fmt.Errorf("%w: discover gateway: %w", ErrNoIPv4Route, err)
	}

	iface, localIP, err := DiscoverInterface()
	if err != nil {
		return nil, err
	}

	return &Route{
		Family:  FamilyV4,
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

type ifaceAddrs struct {
	iface net.Interface
	addrs []net.Addr
}

func routeForGateway(gateway net.IP) (*Route, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("net.Interfaces: %w", err)
	}

	candidates := make([]ifaceAddrs, 0, len(ifaces))
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		candidates = append(candidates, ifaceAddrs{iface: iface, addrs: addrs})
	}

	iface, localIP, err := findIfaceByGateway(candidates, gateway)
	if err != nil {
		return nil, err
	}

	return &Route{
		Family:  FamilyV4,
		Iface:   *iface,
		LocalIP: localIP,
		Gateway: gateway,
	}, nil
}

// findIfaceByGateway returns the first interface that is up, is not a
// loopback, and has an IPv4 subnet containing gateway, together with its
// own address on that subnet.
func findIfaceByGateway(
	candidates []ifaceAddrs,
	gateway net.IP,
) (*net.Interface, net.IP, error) {
	gw4 := gateway.To4()
	if gw4 == nil {
		return nil, nil, fmt.Errorf(
			"gateway %s: IPv6 gateways are not supported yet",
			gateway,
		)
	}

	for i := range candidates {
		iface := &candidates[i].iface
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		for _, addr := range candidates[i].addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			localIP := ipnet.IP.To4()
			if localIP == nil || !ipnet.Contains(gw4) {
				continue
			}
			if localIP.Equal(gw4) {
				return nil, nil, fmt.Errorf(
					"gateway %s is the address of interface %s itself",
					gateway,
					iface.Name,
				)
			}
			return iface, localIP, nil
		}
	}

	return nil, nil, fmt.Errorf(
		"no interface is on the same subnet as gateway %s",
		gateway,
	)
}
