//go:build linux

package tun

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/executil"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/server"
	"golang.zx2c4.com/wireguard/tun"
)

const StateFile = "/tmp/spoofdpi.linux.tun.state"

type tunNetworkInfoLinux struct {
	RouteTableID int
	// GatewayIP is empty when the default route has no gateway.
	GatewayIP        string
	TUNName          string
	PhysIfaceName    string
	PhysIfaceIP      string
	TunLocalIP       string
	TunRemoteIP      string
	RouteTargetCIDRs []string
	IPv6Enabled      bool
	HasIPv6Egress    bool
	TunIPv6Disabled  bool
}

var (
	allocatedTableID   int
	allocatedTableOnce sync.Once
)

func createTunDevice() (tun.Device, error) {
	return tun.CreateTUN("tun-spoofdpi", 1500)
}

func collectNetworkInfo(sysNet *tunSystemNetworkLinux) (*tunNetworkInfoLinux, error) {
	tunName, err := sysNet.TunDevice().Name()
	if err != nil {
		return nil, fmt.Errorf("failed to get tunName: %w", err)
	}
	routeTableID, err := getOrAllocateTableID()
	if err != nil {
		return nil, fmt.Errorf("failed to allocate routing table ID: %w", err)
	}

	gateway := gatewayIP(sysNet.defaultRoute)
	physIfaceName := sysNet.defaultRoute.Iface.Name

	physIfaceIP, err := getInterfaceIP(physIfaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get IP address for interface %s: %w",
			physIfaceName,
			err,
		)
	}

	cidr, err := netutil.FindSafeCIDR()
	if err != nil {
		return nil, fmt.Errorf("failed to find safe subnet: %w", err)
	}

	tunLocalIP, err := netutil.AddrInCIDR(cidr, 1)
	if err != nil {
		return nil, fmt.Errorf("failed to get %dth ip in %s: %w", 1, cidr, err)
	}
	tunRemoteIP, err := netutil.AddrInCIDR(cidr, 2)
	if err != nil {
		return nil, fmt.Errorf("failed to get %dth ip in %s: %w", 2, cidr, err)
	}

	_, tunCIDR, _ := net.ParseCIDR(tunLocalIP + "/30")
	routeTargetCIDRs := []string{tunCIDR.String(), "0.0.0.0/1", "128.0.0.0/1"}

	// Runs before the TUN routes exist, so it sees the system's own route.
	_, hasIPv6Egress := netutil.IPv6Egress()
	tunIPv6Disabled := ipv6Disabled(
		fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/disable_ipv6", tunName),
	)

	return &tunNetworkInfoLinux{ //exhaustruct:enforce
		RouteTableID:     routeTableID,
		GatewayIP:        gateway,
		TUNName:          tunName,
		PhysIfaceName:    physIfaceName,
		PhysIfaceIP:      physIfaceIP,
		TunLocalIP:       tunLocalIP,
		TunRemoteIP:      tunRemoteIP,
		RouteTargetCIDRs: routeTargetCIDRs,
		IPv6Enabled:      sysNet.ipv6Enabled,
		HasIPv6Egress:    hasIPv6Egress,
		TunIPv6Disabled:  tunIPv6Disabled,
	}, nil
}

func (n *tunSystemNetworkLinux) BuildJobs() ([]server.NetworkJob, error) {
	info, err := collectNetworkInfo(n)
	if err != nil {
		return nil, err
	}
	return buildJobs(info), nil
}

// buildJobs returns the jobs that route traffic into the TUN described by
// info.
func buildJobs(info *tunNetworkInfoLinux) []server.NetworkJob {
	var jobs []server.NetworkJob

	jobs = append(jobs, server.NetworkJob{
		Description: "remove TUN interface",
		Reset:       fmt.Sprintf("ip link delete %s", info.TUNName),
	})

	jobs = append(jobs, server.NetworkJob{
		Description: "configure TUN interface address",
		Apply: fmt.Sprintf(
			"ip addr add %s peer %s dev %s",
			info.TunLocalIP,
			info.TunRemoteIP,
			info.TUNName,
		),
		Reset: fmt.Sprintf(
			"ip addr del %s peer %s dev %s",
			info.TunLocalIP,
			info.TunRemoteIP,
			info.TUNName,
		),
	})

	jobs = append(jobs, server.NetworkJob{
		Description: "bring TUN interface up",
		Apply:       fmt.Sprintf("ip link set dev %s up", info.TUNName),
		Reset:       fmt.Sprintf("ip link set dev %s down", info.TUNName),
	})

	// Without a gateway there is no next hop to reach: the default route
	// leaves through the interface itself.
	defaultRouteApply := fmt.Sprintf(
		"ip route add default dev %s table %d",
		info.PhysIfaceName,
		info.RouteTableID,
	)
	if info.GatewayIP != "" {
		jobs = append(jobs, server.NetworkJob{
			Description: "add gateway host route",
			Apply: fmt.Sprintf(
				"ip route add %s dev %s",
				info.GatewayIP,
				info.PhysIfaceName,
			),
			Reset: fmt.Sprintf(
				"ip route del %s dev %s",
				info.GatewayIP,
				info.PhysIfaceName,
			),
		})

		defaultRouteApply = fmt.Sprintf(
			"ip route add default via %s dev %s table %d",
			info.GatewayIP,
			info.PhysIfaceName,
			info.RouteTableID,
		)
	}

	jobs = append(jobs, server.NetworkJob{
		Description: "add default route to routing table",
		Apply:       defaultRouteApply,
		Reset:       fmt.Sprintf("ip route del default table %d", info.RouteTableID),
	})

	jobs = append(jobs, server.NetworkJob{
		Description: "add policy routing rule",
		Apply: fmt.Sprintf(
			"ip rule add from %s lookup %d",
			info.PhysIfaceIP,
			info.RouteTableID,
		),
		Reset: fmt.Sprintf(
			"ip rule del from %s lookup %d",
			info.PhysIfaceIP,
			info.RouteTableID,
		),
	})

	for _, t := range info.RouteTargetCIDRs {
		jobs = append(jobs, server.NetworkJob{
			Description: fmt.Sprintf("add CIDR route %s via TUN", t),
			Apply:       fmt.Sprintf("ip route add %s dev %s", t, info.TUNName),
			Reset:       fmt.Sprintf("ip route del %s dev %s", t, info.TUNName),
		})
	}

	// Without --ipv6, IPv6 is left to the system's routes. With it, the TUN
	// server refuses IPv6, so applications fall back to IPv4. The route is
	// optional: IPv4 keeps working without it.
	if info.IPv6Enabled && info.HasIPv6Egress && !info.TunIPv6Disabled {
		jobs = append(jobs, server.NetworkJob{
			Description: fmt.Sprintf("add IPv6 route %s via TUN", ipv6CaptureCIDR),
			Apply: fmt.Sprintf(
				"ip -6 route add %s dev %s",
				ipv6CaptureCIDR,
				info.TUNName,
			),
			Reset: fmt.Sprintf(
				"ip -6 route del %s dev %s",
				ipv6CaptureCIDR,
				info.TUNName,
			),
			Optional: true,
			Warning:  ipv6RejectWarning,
		})
	}

	return jobs
}

// tunSystemNetworkLinux implements TUNSystemNetwork for Linux
type tunSystemNetworkLinux struct {
	logger       zerolog.Logger
	tunDevice    tun.Device
	defaultRoute *netutil.Route
	ipv6Enabled  bool
}

// NewTUNSystemNetwork creates a new TUNSystemNetwork for TUN mode on Linux
// fibID is ignored on Linux (FreeBSD-specific). IPv6 is routed into the TUN
// only when ipv6Enabled is set.
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

	return &tunSystemNetworkLinux{
		logger:       logger,
		tunDevice:    dev,
		defaultRoute: defaultRoute,
		ipv6Enabled:  ipv6Enabled,
	}, nil
}

func (n *tunSystemNetworkLinux) TunDevice() tun.Device {
	return n.tunDevice
}

func (n *tunSystemNetworkLinux) FIBID() int {
	return 1
}

// EgressControl returns the socket control that binds a socket to the
// physical interface of route with SO_BINDTODEVICE, as TUN mode needs: its
// routes would otherwise carry the traffic into the TUN. fibID is not used
// on Linux. It returns nil when route has no interface. BindDialer pins
// the dialed connections with it, and TUN mode pins the raw sockets of
// fake packets with it too, so the two cannot diverge.
func EgressControl(
	route *netutil.Route,
	fibID int,
) func(network, address string, c syscall.RawConn) error {
	if route == nil || route.Iface.Name == "" {
		return nil
	}
	name := route.Iface.Name
	return func(_, _ string, c syscall.RawConn) error {
		var sockErr error
		err := c.Control(func(fd uintptr) {
			sockErr = syscall.SetsockoptString(
				int(fd),
				syscall.SOL_SOCKET,
				syscall.SO_BINDTODEVICE,
				name,
			)
		})
		if err != nil {
			return fmt.Errorf("failed to control socket: %w", err)
		}
		if sockErr != nil {
			return fmt.Errorf("failed to set SO_BINDTODEVICE: %w", sockErr)
		}
		return nil
	}
}

func (n *tunSystemNetworkLinux) BindDialer(
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

// ipv6Disabled reports whether the disable_ipv6 sysctl file at path reads 1.
// An unreadable file reports false, which leaves the decision to the route
// job, as it is optional.
func ipv6Disabled(path string) bool {
	b, err := os.ReadFile(path)
	return err == nil && strings.TrimSpace(string(b)) == "1"
}

func getOrAllocateTableID() (int, error) {
	var initErr error
	allocatedTableOnce.Do(func() {
		allocatedTableID, initErr = findAvailableTableID()
	})
	if allocatedTableID == 0 {
		return 0, initErr
	}

	return allocatedTableID, nil
}

func findAvailableTableID() (int, error) {
	for id := 200; id <= 250; id++ {
		out, err := executil.Commandf("ip route show table %d", id)
		if err != nil {
			return id, nil
		}

		if len(out) > 0 {
			continue
		}

		ruleTableOut, _ := executil.Commandf("ip rule show table %d", id)
		ruleLookupOut, _ := executil.Commandf("ip rule show lookup %d", id)

		if len(ruleTableOut) > 0 || len(ruleLookupOut) > 0 {
			continue
		}

		return id, nil
	}

	return 0, fmt.Errorf("no available routing table ID in range 200-250")
}

func getInterfaceIP(ifaceName string) (string, error) {
	out, err := executil.Commandf("ip -4 addr show %s", ifaceName)
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "inet ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				ip := strings.Split(parts[1], "/")[0]
				return ip, nil
			}
		}
	}

	return "", fmt.Errorf("IP not found for interface %s", ifaceName)
}
