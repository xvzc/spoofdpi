//go:build darwin

package tun

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/route"
	"github.com/xvzc/spoofdpi/internal/server"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
)

type tunNetworkInfoDarwin struct {
	// Gateway is the zero Addr when the default route has no gateway.
	Gateway        netip.Addr
	PhysIfaceName  string
	PhysIfaceIndex int
	TUNName        string
	TUNIndex       int
	// TunLocal is the TUN's address with the length of its subnet.
	TunLocal         netip.Prefix
	TunRemote        netip.Addr
	RouteTargetCIDRs []netip.Prefix
	IPv6Enabled      bool
	HasIPv6Egress    bool
	// SystemScopedDefault is the scoped default route of the physical
	// interface that is there without TUN mode, or nil when there is none.
	SystemScopedDefault *route.TableRoute
}

func createTunDevice() (tun.Device, error) {
	return tun.CreateTUN("utun", 1500)
}

func collectNetworkInfo(sysNet *tunSystemNetworkDarwin) (*tunNetworkInfoDarwin, error) {
	tunName, err := sysNet.TunDevice().Name()
	if err != nil {
		return nil, fmt.Errorf("failed to get tunName: %w", err)
	}
	tunIface, err := net.InterfaceByName(tunName)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface %s: %w", tunName, err)
	}

	cidr, err := route.FindSafeCIDR()
	if err != nil {
		return nil, fmt.Errorf("failed to find safe subnet: %w", err)
	}
	tunCIDR, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse safe subnet %q: %w", cidr, err)
	}
	tunCIDR = tunCIDR.Masked()
	tunLocalIP := tunCIDR.Addr().Next()
	tunRemoteIP := tunLocalIP.Next()

	routeTargetCIDRs := []netip.Prefix{
		tunCIDR,
		netip.MustParsePrefix("0.0.0.0/1"),
		netip.MustParsePrefix("128.0.0.0/1"),
	}

	// Runs before the TUN routes exist, so it sees the system's own route.
	_, hasIPv6Egress := route.IPv6Egress()

	routes, err := route.DumpRoutes(netutil.FamilyV4, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to read routes: %w", err)
	}
	physIface := sysNet.defaultRoute.Iface

	return &tunNetworkInfoDarwin{ //exhaustruct:enforce
		Gateway:             gateway4(sysNet.defaultRoute),
		PhysIfaceName:       physIface.Name,
		PhysIfaceIndex:      physIface.Index,
		TUNName:             tunName,
		TUNIndex:            tunIface.Index,
		TunLocal:            netip.PrefixFrom(tunLocalIP, tunCIDR.Bits()),
		TunRemote:           tunRemoteIP,
		RouteTargetCIDRs:    routeTargetCIDRs,
		IPv6Enabled:         sysNet.ipv6Enabled,
		HasIPv6Egress:       hasIPv6Egress,
		SystemScopedDefault: systemScopedDefault(routes, physIface.Index),
	}, nil
}

// gateway4 returns the IPv4 gateway of rt, or the zero Addr when rt has
// none, as on a point-to-point uplink such as PPP.
func gateway4(rt *route.Route) netip.Addr {
	gw, _ := netip.AddrFromSlice(rt.Gateway.To4())
	return gw
}

// systemScopedDefault returns the scoped default route of the interface
// with index among routes that TUN mode did not add, or nil when there is
// none. A tagged one is the leftover of a run that CleanLeftovers could
// not remove.
func systemScopedDefault(routes []route.TableRoute, index int) *route.TableRoute {
	for _, r := range routes {
		if isScopedDefault4(r) && r.Index == index && r.Flags&routeTag == 0 {
			return &r
		}
	}
	return nil
}

func (n *tunSystemNetworkDarwin) BuildJobs() ([]server.NetworkJob, error) {
	info, err := collectNetworkInfo(n)
	if err != nil {
		return nil, err
	}
	if info.SystemScopedDefault != nil {
		n.logger.Debug().
			Stringer("route", info.SystemScopedDefault).
			Msg("the physical interface has a scoped default route; not adding one")
	}
	jobs := buildJobs(n.logger, info)
	thisRun.setRoutes(addedRoutes(jobs))
	return jobs, nil
}

// buildJobs returns the jobs that route traffic into the TUN described by
// info. logger gets the warning of a reset that keeps a scoped default
// route that is no longer this run's. The routes through the TUN come before the scoped default route,
// so that while the scoped default route is there, a tagged route through
// a utun shows CleanLeftovers of another run that this run is alive.
func buildJobs(
	logger zerolog.Logger,
	info *tunNetworkInfoDarwin,
) []server.NetworkJob {
	var jobs []server.NetworkJob

	jobs = append(jobs, server.NetworkJob{
		Description: "configure TUN interface address",
		Apply: tunAddrAction{
			name:   info.TUNName,
			local:  info.TunLocal,
			remote: info.TunRemote,
		},
		Reset: linkDownAction{name: info.TUNName},
	})

	for _, t := range info.RouteTargetCIDRs {
		r := tunRoute(info, t)
		jobs = append(jobs, server.NetworkJob{
			Description: fmt.Sprintf("add CIDR route %s via TUN", t),
			Apply:       addRouteAction{route: r},
			Reset:       deleteRouteAction{route: r},
		})
	}

	// The scoped default route lets sockets bound to the physical
	// interface leave through it. One that is already there serves them
	// as well, and is not this run's to delete. Nor is one that replaced
	// this run's while it ran.
	if info.SystemScopedDefault == nil {
		r := scopedDefaultRoute(info)
		jobs = append(jobs, server.NetworkJob{
			Description: "add scoped default route via physical interface",
			Apply:       addRouteAction{route: r},
			Reset:       resetScopedDefaultAction{logger: logger, route: r},
		})
	}

	// Without --ipv6, IPv6 is left to the system's routes. With it, the TUN
	// server refuses IPv6, so applications fall back to IPv4. The route is
	// optional: IPv4 keeps working without it.
	if info.IPv6Enabled && info.HasIPv6Egress {
		r := tunRoute(info, netip.MustParsePrefix(ipv6CaptureCIDR))
		jobs = append(jobs, server.NetworkJob{
			Description: fmt.Sprintf("add IPv6 route %s via TUN", ipv6CaptureCIDR),
			Apply:       addRouteAction{route: r},
			Reset:       deleteRouteAction{route: r},
			Optional:    true,
			Warning:     ipv6RejectWarning,
		})
	}

	return jobs
}

// tunRoute returns the tagged route to dst through the TUN, as
// `route add -net dst -interface tun` adds it.
func tunRoute(info *tunNetworkInfoDarwin, dst netip.Prefix) route.TableRoute {
	return route.TableRoute{
		Dst:         dst,
		GatewayLink: info.TUNIndex,
		IfName:      info.TUNName,
		Flags:       routeTag,
	}
}

// scopedDefaultRoute returns the tagged default route scoped to the
// physical interface, through its gateway, or without a gateway through
// the interface itself, as `route add -ifscope phys default gw` adds it.
func scopedDefaultRoute(info *tunNetworkInfoDarwin) route.TableRoute {
	r := route.TableRoute{
		Dst:     defaultDst4,
		Gateway: info.Gateway,
		Index:   info.PhysIfaceIndex,
		IfName:  info.PhysIfaceName,
		Flags:   routeTag | unix.RTF_IFSCOPE,
	}
	if !info.Gateway.IsValid() {
		r.GatewayLink = info.PhysIfaceIndex
	}
	return r
}

// addedRoutes returns the routes that jobs add.
func addedRoutes(jobs []server.NetworkJob) []route.TableRoute {
	var routes []route.TableRoute
	for _, job := range jobs {
		if a, ok := job.Apply.(addRouteAction); ok {
			routes = append(routes, a.route)
		}
	}
	return routes
}

// tunSystemNetworkDarwin implements TUNSystemNetwork for Darwin
type tunSystemNetworkDarwin struct {
	logger       zerolog.Logger
	tunDevice    tun.Device
	defaultRoute *route.Route
	ipv6Enabled  bool
}

// NewTUNSystemNetwork creates a new TUNSystemNetwork for TUN mode on Darwin
// fibID is ignored on Darwin (FreeBSD-specific). IPv6 is routed into the TUN
// only when ipv6Enabled is set.
func NewTUNSystemNetwork(
	logger zerolog.Logger,
	defaultRoute *route.Route,
	fibID int,
	ipv6Enabled bool,
) (TUNSystemNetwork, error) {
	dev, err := createTunDevice()
	if err != nil {
		return nil, err
	}

	return &tunSystemNetworkDarwin{
		logger:       logger,
		tunDevice:    dev,
		defaultRoute: defaultRoute,
		ipv6Enabled:  ipv6Enabled,
	}, nil
}

func (n *tunSystemNetworkDarwin) TunDevice() tun.Device {
	return n.tunDevice
}

func (n *tunSystemNetworkDarwin) FIBID() int {
	return 1
}

// EgressControl returns the socket control that pins a socket's IPv4
// traffic to the physical interface of rt with IP_BOUND_IF, as TUN mode
// needs: its routes would otherwise carry the traffic into the TUN. fibID
// is not used on darwin. It returns nil when rt has no interface.
// BindDialer pins the dialed connections with it, and TUN mode pins the
// raw sockets of fake packets with it too, so the two cannot diverge.
func EgressControl(
	rt *route.Route,
	fibID int,
) func(network, address string, c syscall.RawConn) error {
	if rt == nil || rt.Iface.Name == "" {
		return nil
	}
	index := rt.Iface.Index
	return func(_, _ string, c syscall.RawConn) error {
		var sockErr error
		err := c.Control(func(fd uintptr) {
			sockErr = syscall.SetsockoptInt(
				int(fd),
				syscall.IPPROTO_IP,
				syscall.IP_BOUND_IF,
				index,
			)
		})
		if err != nil {
			return fmt.Errorf("failed to control socket: %w", err)
		}
		if sockErr != nil {
			return fmt.Errorf("failed to set IP_BOUND_IF: %w", sockErr)
		}
		return nil
	}
}

func (n *tunSystemNetworkDarwin) BindDialer(
	dialer *net.Dialer,
	network string,
	targetIP net.IP,
) error {
	if n.defaultRoute == nil || n.defaultRoute.Iface.Name == "" {
		return nil
	}

	iface := n.defaultRoute.Iface

	addrs, err := iface.Addrs()
	if err != nil {
		return fmt.Errorf("failed to get interface addresses: %w", err)
	}

	var sourceIP net.IP
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if targetIP.To4() != nil && ipnet.IP.To4() != nil && !ipnet.IP.IsLoopback() {
				sourceIP = ipnet.IP
				break
			} else if targetIP.To4() == nil && ipnet.IP.To4() == nil && !ipnet.IP.IsLoopback() {
				sourceIP = ipnet.IP
				break
			}
		}
	}

	if sourceIP == nil {
		return fmt.Errorf(
			"no suitable IP address found on interface %s for target %s",
			n.defaultRoute.Iface.Name,
			targetIP,
		)
	}

	if strings.HasPrefix(network, "tcp") {
		dialer.LocalAddr = &net.TCPAddr{IP: sourceIP}
	} else if strings.HasPrefix(network, "udp") {
		dialer.LocalAddr = &net.UDPAddr{IP: sourceIP}
	} else {
		dialer.LocalAddr = &net.IPAddr{IP: sourceIP}
	}

	dialer.Control = EgressControl(n.defaultRoute, 0)

	return nil
}
