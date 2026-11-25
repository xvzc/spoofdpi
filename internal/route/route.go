package route

import (
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/xvzc/spoofdpi/internal/netutil"
)

// ErrNoIPv4Route is returned, wrapped, by DiscoverRoute when the OS has no
// IPv4 default route, for example on an IPv6-only network, and by RouteTo
// when the kernel has no route to an IPv4 destination.
var ErrNoIPv4Route = errors.New("no IPv4 default route")

// ErrNoGateway is returned, wrapped, by DiscoverRoute when the route to the
// internet has no gateway, such as a point-to-point or VPN link.
var ErrNoGateway = errors.New("route has no gateway")

// addrsOf lists the addresses of iface. Tests replace it.
var addrsOf = func(iface *net.Interface) ([]net.Addr, error) {
	return iface.Addrs()
}

// interfaceByName resolves the interface a zone names. Tests replace it.
var interfaceByName = net.InterfaceByName

// Route represents the default network route of one address family.
type Route struct {
	Family netutil.Family
	Iface  net.Interface
	// LocalIP is the address of Iface on the route, or nil when it is not
	// known.
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

// DiscoverInterface discovers the interface the kernel routes the internet
// through and its local IPv4 address. It does not require a gateway.
func DiscoverInterface() (*net.Interface, net.IP, error) {
	path, err := RouteTo(probeDst(netutil.FamilyV4))
	if err != nil {
		return nil, nil, fmt.Errorf("discover interface: %w", err)
	}

	localIP, err := localIPFor(path)
	if err != nil {
		return nil, nil, err
	}

	return &path.Iface, localIP, nil
}

// DiscoverRoute discovers the default network route.
// If gateway is nil, the gateway IP and interface are resolved from the
// kernel's route to the internet, and ErrNoGateway is returned, wrapped,
// when that route has no gateway. Otherwise the given gateway is used as
// is, and the interface is the one whose subnet contains it, so the two
// always match. An explicit gateway must be an IPv4 address.
func DiscoverRoute(gateway net.IP) (*Route, error) {
	if gateway != nil {
		if gateway.To4() == nil {
			return nil, fmt.Errorf("gateway %s is not an IPv4 address", gateway)
		}
		return routeForGateway(gateway)
	}

	path, err := RouteTo(probeDst(netutil.FamilyV4))
	if err != nil {
		return nil, fmt.Errorf("discover route: %w", err)
	}
	if !path.Gateway.IsValid() {
		return nil, fmt.Errorf(
			"route to %s goes through %s without a gateway: %w",
			path.Dst,
			path.Iface.Name,
			ErrNoGateway,
		)
	}

	localIP, err := localIPFor(path)
	if err != nil {
		return nil, err
	}

	route := path.Route()
	route.LocalIP = localIP
	return route, nil
}

// DiscoverRoute6 discovers the IPv6 default network route.
// If gateway is nil, the route is the kernel's route to the internet; its
// Gateway is nil when that route has no gateway, and its LocalIP is the
// route's source address, if the kernel reported one. Otherwise the given
// gateway is used as is, on the interface that zone names, by name or
// index, if zone is not empty. Without a zone, a link-local gateway is on
// the interface of the kernel's route to the internet, and any other
// gateway on the interface whose subnet contains it.
func DiscoverRoute6(gateway net.IP, zone string) (*Route, error) {
	if gateway == nil {
		path, err := RouteTo(probeDst(netutil.FamilyV6))
		if err != nil {
			return nil, fmt.Errorf("discover route: %w", err)
		}
		return path.Route(), nil
	}

	if gateway.To4() != nil {
		return nil, fmt.Errorf("gateway %s is not an IPv6 address", gateway)
	}

	if zone != "" {
		if !netutil.NeedsZone(gateway) {
			return nil, fmt.Errorf(
				"gateway %s: a zone is allowed only on a link-local address",
				gateway,
			)
		}
		iface, err := ifaceByZone(zone)
		if err != nil {
			return nil, fmt.Errorf("gateway %s: %w", gateway, err)
		}
		return newRoute6(iface, gateway), nil
	}

	if netutil.NeedsZone(gateway) {
		path, err := RouteTo(probeDst(netutil.FamilyV6))
		if err != nil {
			return nil, fmt.Errorf(
				"link-local gateway %s: %w; add a %%<interface> zone to it",
				gateway,
				err,
			)
		}
		return newRoute6(&path.Iface, gateway), nil
	}

	return routeForGateway(gateway)
}

// newRoute6 returns the IPv6 route through gateway on iface.
func newRoute6(iface *net.Interface, gateway net.IP) *Route {
	route := &Route{Family: netutil.FamilyV6, Iface: *iface, Gateway: gateway}
	if netutil.NeedsZone(gateway) {
		route.Zone = iface.Name
	}
	return route
}

// ifaceByZone returns the interface that zone names, by name or by index.
// It must be up and not a loopback.
func ifaceByZone(zone string) (*net.Interface, error) {
	iface, err := interfaceByName(zone)
	if err != nil {
		index, convErr := strconv.Atoi(zone)
		if convErr != nil || index <= 0 {
			return nil, fmt.Errorf("zone %q: %w", zone, err)
		}
		if iface, err = interfaceByIndex(index); err != nil {
			return nil, fmt.Errorf("zone %q: %w", zone, err)
		}
	}
	if iface.Flags&net.FlagUp == 0 {
		return nil, fmt.Errorf("interface %s is down", iface.Name)
	}
	if iface.Flags&net.FlagLoopback != 0 {
		return nil, fmt.Errorf("interface %s is a loopback", iface.Name)
	}
	return iface, nil
}

// localIPFor returns the IPv4 address of the output interface of path: the
// route's own source address when the kernel reported one, and otherwise
// the first IPv4 address of the interface.
func localIPFor(p *Path) (net.IP, error) {
	if p.Src.Is4() {
		return net.IP(p.Src.AsSlice()), nil
	}

	addrs, err := addrsOf(&p.Iface)
	if err != nil {
		return nil, fmt.Errorf("interface %s addresses: %w", p.Iface.Name, err)
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			return ipnet.IP.To4(), nil
		}
	}
	return nil, fmt.Errorf("interface %s has no IPv4 address", p.Iface.Name)
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

	if gateway.To4() == nil {
		route := newRoute6(iface, gateway)
		route.LocalIP = localIP
		return route, nil
	}
	return &Route{
		Family:  netutil.FamilyV4,
		Iface:   *iface,
		LocalIP: localIP,
		Gateway: gateway,
	}, nil
}

// findIfaceByGateway returns the first interface that is up, is not a
// loopback, and has a subnet of gateway's family containing gateway,
// together with its own address on that subnet. IPv6 link-local subnets
// are left out.
func findIfaceByGateway(
	candidates []ifaceAddrs,
	gateway net.IP,
) (*net.Interface, net.IP, error) {
	isV4 := gateway.To4() != nil

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
			if !isV4 {
				if localIP != nil || ipnet.IP.IsLinkLocalUnicast() {
					continue
				}
				localIP = ipnet.IP
			}
			if localIP == nil || !ipnet.Contains(gateway) {
				continue
			}
			if localIP.Equal(gateway) {
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
