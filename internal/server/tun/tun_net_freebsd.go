//go:build freebsd

package tun

import (
	"fmt"
	"net"
	"strings"
	"syscall"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/executil"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/server"
	"golang.zx2c4.com/wireguard/tun"
)

const StateFile = "/tmp/spoofdpi.freebsd.tun.state"

type tunNetworkInfoFreeBSD struct {
	FIBID            int
	GatewayIP        string
	PhysIfaceName    string
	PhysIfaceCIDR    string
	TUNName          string
	TunLocalIP       string
	TunPrefixLen     int
	RouteTargetCIDRs []string
	IPv6Enabled      bool
	HasIPv6Egress    bool
}

func createTunDevice() (tun.Device, error) {
	return tun.CreateTUN("tun-spoofdpi", 1500)
}

func collectNetworkInfo(
	sysNet *tunSystemNetworkFreeBSD,
) (*tunNetworkInfoFreeBSD, error) {
	tunName, err := sysNet.TunDevice().Name()
	if err != nil {
		return nil, fmt.Errorf("failed to get tunName: %w", err)
	}

	// Verify the requested FIB is not already in use.
	if _, err := executil.Commandf(
		"setfib %d route get default",
		sysNet.FIBID(),
	); err == nil {
		return nil, fmt.Errorf("FIB %d is already in use", sysNet.FIBID())
	}

	physIfaceCIDR, err := getInterfaceSubnet(sysNet.defaultRoute.Iface.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface subnet: %w", err)
	}

	cidr, err := netutil.FindSafeCIDR()
	if err != nil {
		return nil, fmt.Errorf("failed to find safe subnet: %w", err)
	}

	tunLocalIP, err := netutil.AddrInCIDR(cidr, 1)
	if err != nil {
		return nil, fmt.Errorf("failed to get %dth ip in %s: %w", 1, cidr, err)
	}
	_, tunNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse safe subnet %s: %w", cidr, err)
	}
	tunPrefixLen, _ := tunNet.Mask.Size()

	// The TUN's own /30 needs no route job: the address below is set with
	// its prefix length, so the kernel adds the /30 interface route.
	routeTargetCIDRs := []string{"0.0.0.0/1", "128.0.0.0/1"}

	// Runs before the TUN routes exist, so it sees the system's own route.
	_, hasIPv6Egress := netutil.IPv6Egress()

	return &tunNetworkInfoFreeBSD{ //exhaustruct:enforce
		FIBID:            sysNet.FIBID(),
		GatewayIP:        sysNet.defaultRoute.Gateway.String(),
		PhysIfaceName:    sysNet.defaultRoute.Iface.Name,
		PhysIfaceCIDR:    physIfaceCIDR,
		TUNName:          tunName,
		TunLocalIP:       tunLocalIP,
		TunPrefixLen:     tunPrefixLen,
		RouteTargetCIDRs: routeTargetCIDRs,
		IPv6Enabled:      sysNet.ipv6Enabled,
		HasIPv6Egress:    hasIPv6Egress,
	}, nil
}

func (n *tunSystemNetworkFreeBSD) BuildJobs() ([]server.NetworkJob, error) {
	info, err := collectNetworkInfo(n)
	if err != nil {
		return nil, err
	}
	return buildJobs(info), nil
}

// buildJobs returns the jobs that route traffic into the TUN described by
// info.
func buildJobs(info *tunNetworkInfoFreeBSD) []server.NetworkJob {
	var jobs []server.NetworkJob

	// wireguard-go puts the FreeBSD tun into IFF_BROADCAST mode, so a
	// destination address would be ignored and ifconfig would fall back to
	// the classful mask, such as 10.0.0.0/8 for a 10.x.y.z address, which
	// would then be routed into the TUN. Set the /30 chosen by FindSafeCIDR
	// explicitly instead.
	jobs = append(jobs, server.NetworkJob{
		Description: "configure TUN interface address",
		Apply: fmt.Sprintf(
			"ifconfig %s inet %s/%d up",
			info.TUNName,
			info.TunLocalIP,
			info.TunPrefixLen,
		),
		Reset: fmt.Sprintf("ifconfig %s destroy", info.TUNName),
	})

	jobs = append(jobs, server.NetworkJob{
		Description: "add FIB subnet route",
		Apply: fmt.Sprintf(
			"route add -net %s -iface %s -fib %d",
			info.PhysIfaceCIDR,
			info.PhysIfaceName,
			info.FIBID,
		),
		Reset: fmt.Sprintf(
			"route delete -net %s -iface %s -fib %d",
			info.PhysIfaceCIDR,
			info.PhysIfaceName,
			info.FIBID,
		),
	})

	jobs = append(jobs, server.NetworkJob{
		Description: "add FIB default route",
		Apply: fmt.Sprintf(
			"route add default %s -fib %d",
			info.GatewayIP,
			info.FIBID,
		),
		Reset: fmt.Sprintf("route delete default -fib %d", info.FIBID),
	})

	for _, t := range info.RouteTargetCIDRs {
		jobs = append(jobs, server.NetworkJob{
			Description: fmt.Sprintf("add CIDR route %s via TUN", t),
			Apply:       fmt.Sprintf("route -n add -net %s -interface %s", t, info.TUNName),
			Reset: fmt.Sprintf(
				"route -n delete -net %s -interface %s",
				t,
				info.TUNName,
			),
		})
	}

	// Without --ipv6, IPv6 is left to the system's routes. With it, the TUN
	// server refuses IPv6, so applications fall back to IPv4. The route is
	// optional: IPv4 keeps working without it.
	if info.IPv6Enabled && info.HasIPv6Egress {
		jobs = append(jobs, server.NetworkJob{
			Description: fmt.Sprintf("add IPv6 route %s via TUN", ipv6CaptureCIDR),
			Apply: fmt.Sprintf(
				"route -n add -inet6 -net %s -interface %s",
				ipv6CaptureCIDR,
				info.TUNName,
			),
			Reset: fmt.Sprintf(
				"route -n delete -inet6 -net %s -interface %s",
				ipv6CaptureCIDR,
				info.TUNName,
			),
			Optional: true,
			Warning:  ipv6RejectWarning,
		})
	}

	return jobs
}

type tunSystemNetworkFreeBSD struct {
	logger       zerolog.Logger
	tunDevice    tun.Device
	defaultRoute *netutil.Route
	fibID        int
	ipv6Enabled  bool
}

// NewTUNSystemNetwork creates a new TUNSystemNetwork for TUN mode on
// FreeBSD. IPv6 is routed into the TUN only when ipv6Enabled is set.
func NewTUNSystemNetwork(
	logger zerolog.Logger,
	defaultRoute *netutil.Route,
	fibID int,
	ipv6Enabled bool,
) (TUNSystemNetwork, error) {
	dev, err := createTunDevice()
	if err != nil {
		return nil, err
	}

	return &tunSystemNetworkFreeBSD{
		logger:       logger,
		tunDevice:    dev,
		defaultRoute: defaultRoute,
		fibID:        fibID,
		ipv6Enabled:  ipv6Enabled,
	}, nil
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
// the TUN. route is not used on FreeBSD. It returns nil when fibID is not
// positive. BindDialer pins the dialed connections with it, and TUN mode
// pins the raw sockets of fake packets with it too, so the two cannot
// diverge.
func EgressControl(
	route *netutil.Route,
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
	if n.fibID <= 0 || n.defaultRoute == nil || n.defaultRoute.Iface.Name == "" {
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

	dialer.Control = EgressControl(n.defaultRoute, n.fibID)

	return nil
}

func getInterfaceSubnet(ifaceName string) (string, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return "", fmt.Errorf("failed to get interface %s: %w", ifaceName, err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return "", fmt.Errorf("failed to get interface addresses: %w", err)
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			network := ipnet.IP.Mask(ipnet.Mask)
			ones, _ := ipnet.Mask.Size()
			subnet := fmt.Sprintf("%s/%d", network.String(), ones)
			return subnet, nil
		}
	}

	return "", fmt.Errorf("no IPv4 address found on interface %s", ifaceName)
}
