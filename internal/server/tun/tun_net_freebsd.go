//go:build freebsd

package tun

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"syscall"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/netif"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/route"
	"github.com/xvzc/spoofdpi/internal/server"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
)

// tunIfName is the name of the TUN interface on FreeBSD. CleanLeftovers
// finds a run that crashed by it.
const tunIfName = "tun-spoofdpi"

// routeTag is the flag that marks the routes spoofdpi adds, so that
// CleanLeftovers can tell them from the routes of others with the same
// shape.
const routeTag = unix.RTF_PROTO2

type tunNetworkInfoFreeBSD struct {
	FIBID int
	// Gateway is the zero Addr when the default route has no gateway.
	Gateway        netip.Addr
	PhysIfaceName  string
	PhysIfaceIndex int
	// PhysIfaceSubnet is the zero Prefix when the FIB needs no subnet
	// route, as needsFIBSubnetRoute decides.
	PhysIfaceSubnet netip.Prefix
	// PhysIfaceP2P reports a point-to-point interface, such as PPP.
	PhysIfaceP2P bool
	// FIBHasSubnetRoute reports that the FIB already has the kernel's
	// route to PhysIfaceSubnet, as with net.add_addr_allfibs=1.
	FIBHasSubnetRoute bool
	TUNName           string
	TUNIndex          int
	// TunAddr is the TUN's local address with the prefix length of its
	// subnet.
	TunAddr       netip.Prefix
	RouteTargets  []netip.Prefix
	IPv6Enabled   bool
	HasIPv6Egress bool
}

func createTunDevice() (tun.Device, error) {
	return tun.CreateTUN(tunIfName, 1500)
}

func collectNetworkInfo(
	sysNet *tunSystemNetworkFreeBSD,
) (*tunNetworkInfoFreeBSD, error) {
	tunName, err := sysNet.TunDevice().Name()
	if err != nil {
		return nil, fmt.Errorf("failed to get tunName: %w", err)
	}
	tunIface, err := net.InterfaceByName(tunName)
	if err != nil {
		return nil, fmt.Errorf("failed to get TUN interface %s: %w", tunName, err)
	}

	fibRoutes, err := route.DumpRoutes(netutil.FamilyV4, sysNet.FIBID())
	if err != nil {
		return nil, fmt.Errorf(
			"failed to read the routes of FIB %d: %w",
			sysNet.FIBID(),
			err,
		)
	}
	var gateway netip.Addr
	if gw := gatewayIP(sysNet.egress4); gw != "" {
		gateway, err = netip.ParseAddr(gw)
		if err != nil {
			return nil, fmt.Errorf("failed to parse gateway %s: %w", gw, err)
		}
		gateway = gateway.Unmap()
	}
	physIfaceP2P := sysNet.egress4.Iface.Flags&net.FlagPointToPoint != 0
	var physIfaceSubnet netip.Prefix
	if needsFIBSubnetRoute(physIfaceP2P, gateway) {
		physIfaceSubnet, err = getInterfaceSubnet(sysNet.egress4.Iface.Name)
		if err != nil {
			return nil, fmt.Errorf("failed to get interface subnet: %w", err)
		}
	}
	if err := checkFIBUnused(sysNet.FIBID(), fibRoutes, physIfaceSubnet); err != nil {
		return nil, err
	}
	fibHasSubnetRoute := hasKernelSubnetRoute(
		fibRoutes,
		physIfaceSubnet,
		sysNet.egress4.Iface.Index,
	)

	cidr, err := route.FindSafeCIDR()
	if err != nil {
		return nil, fmt.Errorf("failed to find safe subnet: %w", err)
	}
	tunSubnet, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse safe subnet %s: %w", cidr, err)
	}
	tunLocalIP, err := route.AddrInCIDR(cidr, 1)
	if err != nil {
		return nil, fmt.Errorf("failed to get %dth ip in %s: %w", 1, cidr, err)
	}
	tunLocalAddr, err := netip.ParseAddr(tunLocalIP)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TUN address %s: %w", tunLocalIP, err)
	}

	// The TUN's own /30 needs no route job: the address below is set with
	// its prefix length, so the kernel adds the /30 interface route.
	routeTargets := mainFIBTargetsV4

	// Runs before the TUN routes exist, so it sees the system's own route.
	_, hasIPv6Egress := route.IPv6Egress()

	return &tunNetworkInfoFreeBSD{ //exhaustruct:enforce
		FIBID:             sysNet.FIBID(),
		Gateway:           gateway,
		PhysIfaceName:     sysNet.egress4.Iface.Name,
		PhysIfaceIndex:    sysNet.egress4.Iface.Index,
		PhysIfaceSubnet:   physIfaceSubnet,
		PhysIfaceP2P:      physIfaceP2P,
		FIBHasSubnetRoute: fibHasSubnetRoute,
		TUNName:           tunName,
		TUNIndex:          tunIface.Index,
		TunAddr:           netip.PrefixFrom(tunLocalAddr, tunSubnet.Bits()),
		RouteTargets:      routeTargets,
		IPv6Enabled:       sysNet.egress6 != nil,
		HasIPv6Egress:     hasIPv6Egress,
	}, nil
}

// checkFIBUnused returns an error when fibRoutes, the IPv4 routes of fib,
// show that fib is not free for this run: it has a default route, or an
// untagged route to subnet, the physical interface's subnet, which the
// subnet route job would fail to add. subnet is the zero Prefix when no
// such job runs. Other routes do not count: the rc scripts add a loopback
// route to every FIB, and a route that clashes with a job fails that job.
// The kernel's own route to subnet does not count either, which
// hasKernelSubnetRoute tells. A default route that CleanLeftovers would
// have removed means that it could not, and the error tells how to remove
// it by hand.
func checkFIBUnused(fib int, fibRoutes []route.TableRoute, subnet netip.Prefix) error {
	for _, r := range fibRoutes {
		if r.Dst.Bits() != 0 {
			if subnet.IsValid() && r.Dst == subnet && !isTaggedRoute(r) &&
				r.Flags&(unix.RTF_STATIC|unix.RTF_GATEWAY) != 0 {
				return fmt.Errorf(
					"FIB %d is already in use: it has the route %s; "+
						"set freebsd-fib to a FIB that only spoofdpi uses, "+
						"or remove the route with '%s'",
					fib, r, manualRouteDelete(fib, r),
				)
			}
			continue
		}
		if isTaggedRoute(r) && isFIBRouteShape(r) {
			return fmt.Errorf(
				"FIB %d still has the default route %s of an earlier spoofdpi "+
					"run, which could not be removed; remove it with '%s'",
				fib, r, manualRouteDelete(fib, r),
			)
		}
		return fmt.Errorf(
			"FIB %d is already in use: it has the default route %s; "+
				"set freebsd-fib to a FIB that only spoofdpi uses",
			fib, r,
		)
	}
	return nil
}

// hasKernelSubnetRoute reports whether fibRoutes hold the route that the
// kernel adds for an address of the interface physIndex in subnet, which
// it adds to every FIB with net.add_addr_allfibs=1.
func hasKernelSubnetRoute(
	fibRoutes []route.TableRoute,
	subnet netip.Prefix,
	physIndex int,
) bool {
	if !subnet.IsValid() {
		return false
	}
	return slices.ContainsFunc(fibRoutes, func(r route.TableRoute) bool {
		return r.Dst == subnet && r.Index == physIndex &&
			r.Flags&(unix.RTF_STATIC|unix.RTF_GATEWAY) == 0
	})
}

func (n *tunSystemNetworkFreeBSD) BuildJobs() ([]server.NetworkJob, error) {
	info, err := collectNetworkInfo(n)
	if err != nil {
		return nil, err
	}
	rememberRun(runInfo{FIB: info.FIBID, TUNName: info.TUNName, TUNIndex: info.TUNIndex})
	return buildJobs(info), nil
}

// buildJobs returns the jobs that route traffic into the TUN described by
// info. Every route they add carries routeTag.
func buildJobs(info *tunNetworkInfoFreeBSD) []server.NetworkJob {
	var jobs []server.NetworkJob

	// wireguard-go puts the FreeBSD tun into IFF_BROADCAST mode, so a
	// destination address would be read as the broadcast address. The
	// address goes without one, with the /30 chosen by FindSafeCIDR as its
	// netmask. The TUN cannot be destroyed while spoofdpi holds it open, so
	// the reset only removes the address; closing the TUN at shutdown
	// destroys it.
	jobs = append(jobs, server.NetworkJob{
		Description: "configure TUN interface address",
		Apply:       tunAddressAddAction{Name: info.TUNName, Addr: info.TunAddr},
		Reset:       tunAddressDeleteAction{Name: info.TUNName, Addr: info.TunAddr.Addr()},
	})

	// With the kernel's own route to the subnet in the FIB, the job would
	// fail as a duplicate, and its reset would delete the kernel's route.
	if needsFIBSubnetRoute(info.PhysIfaceP2P, info.Gateway) && !info.FIBHasSubnetRoute {
		jobs = append(jobs, routeJob(
			"add FIB subnet route",
			info.FIBID,
			route.TableRoute{
				Dst:         info.PhysIfaceSubnet,
				GatewayLink: info.PhysIfaceIndex,
				IfName:      info.PhysIfaceName,
				Flags:       routeTag,
			},
		))
	}

	// Without a gateway, the FIB default route leaves through the
	// interface itself.
	fibDefault := route.TableRoute{
		Dst:     netip.PrefixFrom(netip.IPv4Unspecified(), 0),
		Gateway: info.Gateway,
		Flags:   routeTag,
	}
	if !info.Gateway.IsValid() {
		fibDefault.GatewayLink = info.PhysIfaceIndex
		fibDefault.IfName = info.PhysIfaceName
	}
	jobs = append(jobs, routeJob("add FIB default route", info.FIBID, fibDefault))

	for _, t := range info.RouteTargets {
		jobs = append(jobs, routeJob(
			fmt.Sprintf("add CIDR route %s via TUN", t),
			mainFIB,
			tunRoute(t, info),
		))
	}

	// Without --ipv6, IPv6 is left to the system's routes. With it, the TUN
	// server refuses IPv6, so applications fall back to IPv4. The route is
	// optional: IPv4 keeps working without it.
	if info.IPv6Enabled && info.HasIPv6Egress {
		job := routeJob(
			fmt.Sprintf("add IPv6 route %s via TUN", ipv6CaptureCIDR),
			mainFIB,
			tunRoute(mainFIBTargetV6, info),
		)
		job.Optional = true
		job.Warning = ipv6RejectWarning
		jobs = append(jobs, job)
	}

	return jobs
}

// mainFIB is the FIB of the processes that do not set one, whose traffic
// the TUN captures.
const mainFIB = 0

// mainFIBTargetsV4 are the IPv4 destinations routed into the TUN in the
// main FIB. Together they cover all addresses, and each is longer than the
// default route, so they win over it without replacing it.
var mainFIBTargetsV4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/1"),
	netip.MustParsePrefix("128.0.0.0/1"),
}

// mainFIBTargetV6 is ipv6CaptureCIDR as a prefix.
var mainFIBTargetV6 = netip.MustParsePrefix(ipv6CaptureCIDR)

// tunRoute returns the tagged route of dst through the TUN of info, as
// `route add -net dst -interface tun` adds it.
func tunRoute(dst netip.Prefix, info *tunNetworkInfoFreeBSD) route.TableRoute {
	return route.TableRoute{
		Dst:         dst,
		GatewayLink: info.TUNIndex,
		IfName:      info.TUNName,
		Flags:       routeTag,
	}
}

// routeJob returns the job that adds r to fib and deletes it again. The
// delete carries the gateway of r, so it removes only that route.
func routeJob(description string, fib int, r route.TableRoute) server.NetworkJob {
	return server.NetworkJob{
		Description: description,
		Apply:       routeAddAction{FIB: fib, Route: r},
		Reset:       routeDeleteAction{FIB: fib, Route: r},
	}
}

// routeAddAction adds Route to the routing table of FIB.
type routeAddAction struct {
	FIB   int
	Route route.TableRoute
}

func (a routeAddAction) Run() error {
	return route.AddRoute(a.FIB, a.Route)
}

func (a routeAddAction) String() string {
	return fmt.Sprintf("add route %s to fib %d", a.Route, a.FIB)
}

// routeDeleteAction deletes Route from the routing table of FIB.
type routeDeleteAction struct {
	FIB   int
	Route route.TableRoute
}

func (a routeDeleteAction) Run() error {
	return route.DeleteRoute(a.FIB, a.Route)
}

func (a routeDeleteAction) String() string {
	return fmt.Sprintf("delete route %s from fib %d", a.Route, a.FIB)
}

// tunAddressAddAction sets Addr on the interface Name and brings it up, as
// `ifconfig Name inet Addr up` does.
type tunAddressAddAction struct {
	Name string
	Addr netip.Prefix
}

func (a tunAddressAddAction) Run() error {
	if err := netif.AddAddr4(a.Name, a.Addr, netip.Addr{}); err != nil {
		return err
	}
	return netif.SetUp(a.Name)
}

func (a tunAddressAddAction) String() string {
	return fmt.Sprintf("set address %s on %s and bring it up", a.Addr, a.Name)
}

// tunAddressDeleteAction deletes Addr from the interface Name, which also
// removes the route to its subnet.
type tunAddressDeleteAction struct {
	Name string
	Addr netip.Addr
}

func (a tunAddressDeleteAction) Run() error {
	return netif.DelAddr4(a.Name, a.Addr)
}

func (a tunAddressDeleteAction) String() string {
	return fmt.Sprintf("delete address %s from %s", a.Addr, a.Name)
}

// needsFIBSubnetRoute reports whether the FIB needs a route to the
// physical interface's subnet, given whether the interface is
// point-to-point and its gateway, the zero Addr when there is none. A
// point-to-point interface without a gateway reaches the internet through
// the interface itself, so its subnet needs no route; with a gateway, the
// FIB keeps the subnet route that reaches that gateway.
func needsFIBSubnetRoute(physIfaceP2P bool, gateway netip.Addr) bool {
	return !physIfaceP2P || gateway.IsValid()
}

type tunSystemNetworkFreeBSD struct {
	logger    zerolog.Logger
	tunDevice tun.Device
	egress4   *route.Route
	// egress6 is nil when IPv6 is off.
	egress6 *route.Route
	fibID   int
}

// NewTUNSystemNetwork creates a new TUNSystemNetwork for TUN mode on
// FreeBSD with the IPv4 and IPv6 egresses, which routes spoofdpi's own
// traffic through FIB fibID. It fails when the kernel has no such FIB.
// egress6 is nil when IPv6 is off; IPv6 is routed into the TUN only when
// it is not.
func NewTUNSystemNetwork(
	logger zerolog.Logger,
	egress4, egress6 *route.Route,
	fibID int,
) (TUNSystemNetwork, error) {
	fibs, err := unix.SysctlUint32("net.fibs")
	if err != nil {
		return nil, fmt.Errorf("failed to read net.fibs: %w", err)
	}
	if err := checkFIBNumber(fibID, int(fibs)); err != nil {
		return nil, err
	}

	dev, err := createTunDevice()
	if err != nil {
		return nil, err
	}

	return &tunSystemNetworkFreeBSD{
		logger:    logger,
		tunDevice: dev,
		egress4:   egress4,
		egress6:   egress6,
		fibID:     fibID,
	}, nil
}

// checkFIBNumber returns an error unless fib is a FIB other than the main
// one among the fibs FIBs of the kernel (net.fibs).
func checkFIBNumber(fib, fibs int) error {
	if fib >= 1 && fib < fibs {
		return nil
	}
	return fmt.Errorf(
		"freebsd-fib %d is not available: the kernel has %d FIBs (net.fibs), "+
			"and spoofdpi needs one of FIBs 1 to net.fibs-1 for itself alone; "+
			"to add FIBs, run 'sysctl net.fibs=%d' or set net.fibs in "+
			"/boot/loader.conf",
		fib, fibs, max(fib+1, 2),
	)
}

func (n *tunSystemNetworkFreeBSD) TunDevice() tun.Device {
	return n.tunDevice
}

func (n *tunSystemNetworkFreeBSD) FIBID() int {
	return n.fibID
}

// EgressControl returns the socket control that puts a socket in FIB
// fibID with SO_SETFIB, whose default route is the physical one, as TUN
// mode needs: the main FIB's routes would otherwise carry the traffic into
// the TUN. The FIB applies to IPv4 and IPv6 sockets alike, so rt, of
// either family, is not used on FreeBSD. The FIB has only an IPv4 default
// route for now; its IPv6 default route is added in a later step (B2).
// It returns nil when fibID is not positive. BindDialer pins the dialed
// connections with it, and TUN mode pins the raw sockets of fake packets
// with it too, so the two cannot diverge.
func EgressControl(
	rt *route.Route,
	fibID int,
) func(network, address string, c syscall.RawConn) error {
	if fibID <= 0 {
		return nil
	}
	return func(_, _ string, c syscall.RawConn) error {
		var sockErr error
		err := c.Control(func(fd uintptr) {
			sockErr = syscall.SetsockoptInt(
				int(fd),
				syscall.SOL_SOCKET,
				syscall.SO_SETFIB,
				fibID,
			)
		})
		if err != nil {
			return fmt.Errorf("failed to control socket: %w", err)
		}
		if sockErr != nil {
			return fmt.Errorf("failed to set SO_SETFIB to %d: %w", fibID, sockErr)
		}
		return nil
	}
}

func (n *tunSystemNetworkFreeBSD) BindDialer(
	dialer *net.Dialer,
	network string,
	targetIP net.IP,
) error {
	if n.fibID <= 0 {
		return nil
	}
	rt, err := egressFor(n.egress4, n.egress6, targetIP)
	if err != nil {
		return err
	}
	return bindEgress(dialer, network, targetIP, rt, EgressControl(rt, n.fibID))
}

// getInterfaceSubnet returns the subnet of the first IPv4 address of the
// interface ifaceName.
func getInterfaceSubnet(ifaceName string) (netip.Prefix, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("failed to get interface %s: %w", ifaceName, err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("failed to get interface addresses: %w", err)
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			ip, _ := netip.AddrFromSlice(ipnet.IP.To4())
			ones, _ := ipnet.Mask.Size()
			return netip.PrefixFrom(ip, ones).Masked(), nil
		}
	}

	return netip.Prefix{}, fmt.Errorf("no IPv4 address found on interface %s", ifaceName)
}
