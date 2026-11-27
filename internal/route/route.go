package route

import (
	"errors"
	"fmt"
	"net"

	"github.com/xvzc/spoofdpi/internal/netutil"
)

// ErrNoIPv4 is returned, wrapped, by InternetInterface when the OS has no
// IPv4 default route, for example on an IPv6-only network, and by Lookup
// when the kernel has no route to an IPv4 destination.
var ErrNoIPv4 = errors.New("no IPv4 default route")

// addrsOf lists the addresses of iface. Tests replace it.
var addrsOf = func(iface *net.Interface) ([]net.Addr, error) {
	return iface.Addrs()
}

// Route is a route of one address family: the interface traffic leaves
// through and its gateway, which is nil for an interface route.
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

// GatewayString returns the gateway address with its zone, if any, such
// as "192.168.1.1" or "fe80::1%en0".
func (r *Route) GatewayString() string {
	if r.Zone == "" {
		return r.Gateway.String()
	}
	return r.Gateway.String() + "%" + r.Zone
}

// InternetInterface discovers the interface the kernel routes the internet
// through and its local IPv4 address. It does not require a gateway.
func InternetInterface() (*net.Interface, net.IP, error) {
	path, err := Lookup(probeDst(netutil.FamilyV4))
	if err != nil {
		return nil, nil, fmt.Errorf("discover interface: %w", err)
	}

	localIP, err := localIPFor(path)
	if err != nil {
		return nil, nil, err
	}

	return &path.Iface, localIP, nil
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
