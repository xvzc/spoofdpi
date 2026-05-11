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
	TunRemoteIP      string
	RouteTargetCIDRs []string
}

func createTunDevice() (tun.Device, error) {
	return tun.CreateTUN("tun-spoofdpi", 1500)
}

func collectNetworkInfo(sysNet TUNSystemNetwork) (*tunNetworkInfoFreeBSD, error) {
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

	physIfaceCIDR, err := getInterfaceSubnet(sysNet.DefaultRoute().Iface.Name)
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
	tunRemoteIP, err := netutil.AddrInCIDR(cidr, 2)
	if err != nil {
		return nil, fmt.Errorf("failed to get %dth ip in %s: %w", 2, cidr, err)
	}

	_, tunCIDR, _ := net.ParseCIDR(tunLocalIP + "/30")
	routeTargetCIDRs := []string{tunCIDR.String(), "0.0.0.0/1", "128.0.0.0/1"}

	return &tunNetworkInfoFreeBSD{ //exhaustruct:enforce
		FIBID:            sysNet.FIBID(),
		GatewayIP:        sysNet.DefaultRoute().Gateway.String(),
		PhysIfaceName:    sysNet.DefaultRoute().Iface.Name,
		PhysIfaceCIDR:    physIfaceCIDR,
		TUNName:          tunName,
		TunLocalIP:       tunLocalIP,
		TunRemoteIP:      tunRemoteIP,
		RouteTargetCIDRs: routeTargetCIDRs,
	}, nil
}

func (n *tunSystemNetworkFreeBSD) BuildJobs() ([]netutil.NetworkJob, error) {
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

	jobs = append(jobs, netutil.NetworkJob{
		Description: "add FIB default route",
		Apply: fmt.Sprintf(
			"route add default %s -fib %d",
			info.GatewayIP,
			info.FIBID,
		),
		Reset: fmt.Sprintf("route delete default -fib %d", info.FIBID),
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

type tunSystemNetworkFreeBSD struct {
	logger       zerolog.Logger
	tunDevice    tun.Device
	defaultRoute *netutil.Route
	fibID        int
}

func NewTUNSystemNetwork(
	logger zerolog.Logger,
	defaultRoute *netutil.Route,
	fibID int,
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
	}, nil
}

func (n *tunSystemNetworkFreeBSD) TunDevice() tun.Device {
	return n.tunDevice
}

func (n *tunSystemNetworkFreeBSD) DefaultRoute() *netutil.Route {
	return n.defaultRoute
}

func (n *tunSystemNetworkFreeBSD) FIBID() int {
	return n.fibID
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

	dialer.Control = func(network, address string, c syscall.RawConn) error {
		var sockErr error
		err := c.Control(func(fd uintptr) {
			sockErr = syscall.SetsockoptInt(
				int(fd),
				syscall.SOL_SOCKET,
				syscall.SO_SETFIB,
				n.fibID,
			)
		})
		if err != nil {
			return fmt.Errorf("failed to control socket: %w", err)
		}
		if sockErr != nil {
			return fmt.Errorf("failed to set SO_SETFIB to %d: %w", n.fibID, sockErr)
		}
		return nil
	}

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
