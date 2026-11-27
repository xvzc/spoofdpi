//go:build darwin

package tun

import (
	"fmt"
	"net"
	"strings"
	"syscall"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/route"
	"github.com/xvzc/spoofdpi/internal/server"
	"golang.zx2c4.com/wireguard/tun"
)

type tunNetworkInfoDarwin struct {
	// GatewayIP is empty when the default route has no gateway.
	GatewayIP        string
	PhysIfaceName    string
	TUNName          string
	TunLocalIP       string
	TunRemoteIP      string
	RouteTargetCIDRs []string
	IPv6Enabled      bool
	HasIPv6Egress    bool
}

func createTunDevice() (tun.Device, error) {
	return tun.CreateTUN("utun", 1500)
}

func collectNetworkInfo(sysNet *tunSystemNetworkDarwin) (*tunNetworkInfoDarwin, error) {
	tunName, err := sysNet.TunDevice().Name()
	if err != nil {
		return nil, fmt.Errorf("failed to get tunName: %w", err)
	}

	cidr, err := route.FindSafeCIDR()
	if err != nil {
		return nil, fmt.Errorf("failed to find safe subnet: %w", err)
	}

	tunLocalIP, err := route.AddrInCIDR(cidr, 1)
	if err != nil {
		return nil, fmt.Errorf("failed to get %dth ip in %s: %w", 1, cidr, err)
	}
	tunRemoteIP, err := route.AddrInCIDR(cidr, 2)
	if err != nil {
		return nil, fmt.Errorf("failed to get %dth ip in %s: %w", 2, cidr, err)
	}

	_, tunCIDR, _ := net.ParseCIDR(tunLocalIP + "/30")
	routeTargetCIDRs := []string{tunCIDR.String(), "0.0.0.0/1", "128.0.0.0/1"}

	// Runs before the TUN routes exist, so it sees the system's own route.
	_, hasIPv6Egress := route.IPv6Egress()

	return &tunNetworkInfoDarwin{ //exhaustruct:enforce
		GatewayIP:        gatewayIP(sysNet.defaultRoute),
		PhysIfaceName:    sysNet.defaultRoute.Iface.Name,
		TUNName:          tunName,
		TunLocalIP:       tunLocalIP,
		TunRemoteIP:      tunRemoteIP,
		RouteTargetCIDRs: routeTargetCIDRs,
		IPv6Enabled:      sysNet.ipv6Enabled,
		HasIPv6Egress:    hasIPv6Egress,
	}, nil
}

func (n *tunSystemNetworkDarwin) BuildJobs() ([]server.NetworkJob, error) {
	info, err := collectNetworkInfo(n)
	if err != nil {
		return nil, err
	}
	return buildJobs(info), nil
}

// buildJobs returns the jobs that route traffic into the TUN described by
// info.
func buildJobs(info *tunNetworkInfoDarwin) []server.NetworkJob {
	var jobs []server.NetworkJob

	jobs = append(jobs, server.NetworkJob{
		Description: "configure TUN interface address",
		Apply: server.CommandAction{
			"ifconfig", info.TUNName, info.TunLocalIP, info.TunRemoteIP, "up",
		},
		Reset: server.CommandAction{"ifconfig", info.TUNName, "down"},
	})

	// Without a gateway, the scoped default route leaves through the
	// interface itself.
	scopedDefaultTarget := []string{info.GatewayIP}
	if info.GatewayIP == "" {
		scopedDefaultTarget = []string{"-interface", info.PhysIfaceName}
	}
	jobs = append(jobs, server.NetworkJob{
		Description: "add scoped default route via physical interface",
		Apply: append(
			server.CommandAction{"route", "add", "-ifscope", info.PhysIfaceName, "default"},
			scopedDefaultTarget...,
		),
		Reset: append(
			server.CommandAction{
				"route",
				"delete",
				"-ifscope",
				info.PhysIfaceName,
				"default",
			},
			scopedDefaultTarget...,
		),
	})

	for _, t := range info.RouteTargetCIDRs {
		jobs = append(jobs, server.NetworkJob{
			Description: fmt.Sprintf("add CIDR route %s via TUN", t),
			Apply: server.CommandAction{
				"route", "-n", "add", "-net", t, "-interface", info.TUNName,
			},
			Reset: server.CommandAction{
				"route", "-n", "delete", "-net", t, "-interface", info.TUNName,
			},
		})
	}

	// Without --ipv6, IPv6 is left to the system's routes. With it, the TUN
	// server refuses IPv6, so applications fall back to IPv4. The route is
	// optional: IPv4 keeps working without it.
	if info.IPv6Enabled && info.HasIPv6Egress {
		jobs = append(jobs, server.NetworkJob{
			Description: fmt.Sprintf("add IPv6 route %s via TUN", ipv6CaptureCIDR),
			Apply: server.CommandAction{
				"route", "-n", "add", "-inet6", "-net", ipv6CaptureCIDR,
				"-interface", info.TUNName,
			},
			Reset: server.CommandAction{
				"route", "-n", "delete", "-inet6", "-net", ipv6CaptureCIDR,
				"-interface", info.TUNName,
			},
			Optional: true,
			Warning:  ipv6RejectWarning,
		})
	}

	return jobs
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
