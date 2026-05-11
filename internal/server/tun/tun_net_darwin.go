//go:build darwin

package tun

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/server"
	"golang.zx2c4.com/wireguard/tun"
)

const stateFile = "/tmp/spoofdpi.darwin.tun.state"

type tunStateDarwin struct {
	GatewayIP        string    `json:"gatewayIP"`
	PhysIfaceName    string    `json:"physIfaceName"`
	TUNName          string    `json:"tunName"`
	TunLocalIP       string    `json:"tunLocalIP"`
	TunRemoteIP      string    `json:"tunRemoteIP"`
	RouteTargetCIDRs []string  `json:"routeTargetCIDRs"`
	CreatedAt        time.Time `json:"createdAt"`
}

func createTunDevice() (tun.Device, error) {
	return tun.CreateTUN("utun", 1500)
}

func createState(sysNet TUNSystemNetwork) (*tunStateDarwin, error) {
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

	return &tunStateDarwin{ //exhaustruct:enforce
		GatewayIP:        sysNet.DefaultRoute().Gateway.String(),
		PhysIfaceName:    sysNet.DefaultRoute().Iface.Name,
		TUNName:          tunName,
		TunLocalIP:       tunLocalIP,
		TunRemoteIP:      tunRemoteIP,
		RouteTargetCIDRs: routeTargetCIDRs,
		CreatedAt:        time.Now(),
	}, nil
}

func buildJobs(state *tunStateDarwin) []server.NetworkJob {
	_, tunCIDR, _ := net.ParseCIDR(state.TunLocalIP + "/30")
	targets := []string{tunCIDR.String(), "0.0.0.0/1", "128.0.0.0/1"}

	var cidrUp, cidrDown []string
	for _, t := range targets {
		cidrUp = append(
			cidrUp,
			fmt.Sprintf("route -n add -net %s -interface %s", t, state.TUNName),
		)
		cidrDown = append(
			cidrDown,
			fmt.Sprintf("route -n delete -net %s -interface %s", t, state.TUNName),
		)
	}
	for i, j := 0, len(cidrDown)-1; i < j; i, j = i+1, j-1 {
		cidrDown[i], cidrDown[j] = cidrDown[j], cidrDown[i]
	}

	return []server.NetworkJob{
		{
			Description: "configure TUN interface address",
			Up: []string{
				fmt.Sprintf(
					"ifconfig %s %s %s up",
					state.TUNName,
					state.TunLocalIP,
					state.TunRemoteIP,
				),
			},
			Down: []string{fmt.Sprintf("ifconfig %s destroy", state.TUNName)},
		},
		{
			Description: "add scoped default route via physical interface",
			Up: []string{
				fmt.Sprintf(
					"route add -ifscope %s default %s",
					state.PhysIfaceName,
					state.GatewayIP,
				),
			},
			Down: []string{
				fmt.Sprintf(
					"route delete -ifscope %s default %s",
					state.PhysIfaceName,
					state.GatewayIP,
				),
			},
		},
		{
			Description: "add host route for gateway",
			Up: []string{
				fmt.Sprintf(
					"route -n add -host %s -interface %s",
					state.GatewayIP,
					state.PhysIfaceName,
				),
			},
			Down: []string{
				fmt.Sprintf(
					"route -n delete -host %s -interface %s",
					state.GatewayIP,
					state.PhysIfaceName,
				),
			},
		},
		{
			Description: "add CIDR routes via TUN",
			Up:          cidrUp,
			Down:        cidrDown,
		},
	}
}

func saveState(jobs []server.NetworkJob) error {
	type state struct {
		Jobs      []server.NetworkJob `json:"jobs"`
		CreatedAt time.Time           `json:"createdAt"`
	}
	data, err := json.Marshal(state{Jobs: jobs, CreatedAt: time.Now()})
	if err != nil {
		return err
	}
	return os.WriteFile(stateFile, data, 0o644)
}

func loadState() ([]server.NetworkJob, bool, error) {
	type state struct {
		Jobs []server.NetworkJob `json:"jobs"`
	}
	data, err := os.ReadFile(stateFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	var s state
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, false, err
	}
	return s.Jobs, true, nil
}

func deleteState() error {
	if err := os.Remove(stateFile); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// tunSystemNetworkDarwin implements TUNSystemNetwork for Darwin
type tunSystemNetworkDarwin struct {
	logger       zerolog.Logger
	tunDevice    tun.Device
	defaultRoute *netutil.Route
}

// NewTUNSystemNetwork creates a new TUNSystemNetwork for TUN mode on Darwin
// fibID is ignored on Darwin (FreeBSD-specific)
func NewTUNSystemNetwork(
	logger zerolog.Logger,
	defaultRoute *netutil.Route,
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

func (n *tunSystemNetworkDarwin) DefaultRoute() *netutil.Route {
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
