//go:build darwin

package tun

import (
	"fmt"
	"net"
	"strings"
	"syscall"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/packet"
	"golang.zx2c4.com/wireguard/tun"
)

const StateFile = "/tmp/spoofdpi.darwin.tun.state"

type tunNetworkInfoDarwin struct {
	GatewayIP        string
	PhysIfaceName    string
	TUNName          string
	TunLocalIP       string
	TunRemoteIP      string
	RouteTargetCIDRs []string
}

func createTunDevice() (tun.Device, error) {
	return tun.CreateTUN("utun", 1500)
}

func collectNetworkInfo(sysNet TUNSystemNetwork) (*tunNetworkInfoDarwin, error) {
	tunName, err := sysNet.TunDevice().Name()
	if err != nil {
		return nil, fmt.Errorf("failed to get tunName: %w", err)
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

	return &tunNetworkInfoDarwin{ //exhaustruct:enforce
		GatewayIP:        sysNet.DefaultRoute().Gateway.String(),
		PhysIfaceName:    sysNet.DefaultRoute().Iface.Name,
		TUNName:          tunName,
		TunLocalIP:       tunLocalIP,
		TunRemoteIP:      tunRemoteIP,
		RouteTargetCIDRs: routeTargetCIDRs,
	}, nil
}

func (n *tunSystemNetworkDarwin) BuildJobs() ([]netutil.NetworkJob, error) {
	info, err := collectNetworkInfo(n)
	if err != nil {
		return nil, err
	}

	var jobs []netutil.NetworkJob

	jobs = append(jobs, netutil.NetworkJob{
		Description: "configure TUN interface address",
		Apply: fmt.Sprintf(
			"ifconfig %s %s %s up",
			info.TUNName,
			info.TunLocalIP,
			info.TunRemoteIP,
		),
		Reset: fmt.Sprintf("ifconfig %s destroy", info.TUNName),
	})

	jobs = append(jobs, netutil.NetworkJob{
		Description: "add scoped default route via physical interface",
		Apply: fmt.Sprintf(
			"route add -ifscope %s default %s",
			info.PhysIfaceName,
			info.GatewayIP,
		),
		Reset: fmt.Sprintf(
			"route delete -ifscope %s default %s",
			info.PhysIfaceName,
			info.GatewayIP,
		),
	})

	for _, t := range info.RouteTargetCIDRs {
		jobs = append(jobs, netutil.NetworkJob{
			Description: fmt.Sprintf("add CIDR route %s via TUN", t),
			Apply:       fmt.Sprintf("route -n add -net %s -interface %s", t, info.TUNName),
			Reset: fmt.Sprintf(
				"route -n delete -net %s -interface %s",
				t,
				info.TUNName,
			),
		})
	}

	return jobs, nil
}

// tunSystemNetworkDarwin implements TUNSystemNetwork for Darwin
type tunSystemNetworkDarwin struct {
	logger       zerolog.Logger
	tunDevice    tun.Device
	defaultRoute *packet.Route
}

// NewTUNSystemNetwork creates a new TUNSystemNetwork for TUN mode on Darwin
// fibID is ignored on Darwin (FreeBSD-specific)
func NewTUNSystemNetwork(
	logger zerolog.Logger,
	defaultRoute *packet.Route,
	fibID int,
) (TUNSystemNetwork, error) {
	dev, err := createTunDevice()
	if err != nil {
		return nil, err
	}

	return &tunSystemNetworkDarwin{
		logger:       logger,
		tunDevice:    dev,
		defaultRoute: defaultRoute,
	}, nil
}

func (n *tunSystemNetworkDarwin) TunDevice() tun.Device {
	return n.tunDevice
}

func (n *tunSystemNetworkDarwin) DefaultRoute() *packet.Route {
	return n.defaultRoute
}

func (n *tunSystemNetworkDarwin) FIBID() int {
	return 1
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

	dialer.Control = func(network, address string, c syscall.RawConn) error {
		var sockErr error
		err := c.Control(func(fd uintptr) {
			sockErr = syscall.SetsockoptInt(
				int(fd),
				syscall.IPPROTO_IP,
				syscall.IP_BOUND_IF,
				iface.Index,
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

	return nil
}
