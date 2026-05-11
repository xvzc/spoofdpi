//go:build linux

package tun

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/executil"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/server"
	"golang.zx2c4.com/wireguard/tun"
)

const stateFile = "/tmp/spoofdpi.linux.tun.state"

type tunStateLinux struct {
	RouteTableID     int       `json:"routeTableID"`
	GatewayIP        string    `json:"gatewayIP"`
	TUNName          string    `json:"tunName"`
	PhysIfaceName    string    `json:"physIfaceName"`
	PhysIfaceIP      string    `json:"ifaceIP"`
	TunLocalIP       string    `json:"tunLocalIP"`
	TunRemoteIP      string    `json:"tunRemoteIP"`
	RouteTargetCIDRs []string  `json:"routeTargetCIDRs"`
	CreatedAt        time.Time `json:"createdAt"`
}

var (
	allocatedTableID   int
	allocatedTableOnce sync.Once
)

func createTunDevice() (tun.Device, error) {
	return tun.CreateTUN("tun-spoofdpi", 1500)
}

func createState(sysNet TUNSystemNetwork) (*tunStateLinux, error) {
	var err error

	tunName, err := sysNet.TunDevice().Name()
	if err != nil {
		return nil, fmt.Errorf("failed to get tunName: %w", err)
	}
	routeTableID, err := getOrAllocateTableID()
	if err != nil {
		return nil, fmt.Errorf("failed to allocate routing table ID: %w", err)
	}

	gatewayIP := sysNet.DefaultRoute().Gateway.String()
	physIfaceName := sysNet.DefaultRoute().Iface.Name

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

	return &tunStateLinux{ //exhaustruct:enforce
		RouteTableID:     routeTableID,
		GatewayIP:        gatewayIP,
		TUNName:          tunName,
		PhysIfaceName:    physIfaceName,
		PhysIfaceIP:      physIfaceIP,
		TunLocalIP:       tunLocalIP,
		TunRemoteIP:      tunRemoteIP,
		RouteTargetCIDRs: routeTargetCIDRs,
		CreatedAt:        time.Now(),
	}, nil
}

func buildJobs(state *tunStateLinux) []server.NetworkJob {
	var jobs []server.NetworkJob

	jobs = append(jobs, server.NetworkJob{
		Description: "remove TUN interface",
		Up:          nil,
		Down:        []string{fmt.Sprintf("ip link delete %s", state.TUNName)},
	})

	jobs = append(jobs, server.NetworkJob{
		Description: "configure TUN interface address",
		Up: []string{
			fmt.Sprintf(
				"ip addr add %s peer %s dev %s",
				state.TunLocalIP,
				state.TunRemoteIP,
				state.TUNName,
			),
		},
		Down: []string{
			fmt.Sprintf(
				"ip addr del %s peer %s dev %s",
				state.TunLocalIP,
				state.TunRemoteIP,
				state.TUNName,
			),
		},
	})

	jobs = append(jobs, server.NetworkJob{
		Description: "bring TUN interface up",
		Up:          []string{fmt.Sprintf("ip link set dev %s up", state.TUNName)},
		Down:        []string{fmt.Sprintf("ip link set dev %s down", state.TUNName)},
	})

	jobs = append(jobs, server.NetworkJob{
		Description: "add gateway host route",
		Up: []string{
			fmt.Sprintf("ip route add %s dev %s", state.GatewayIP, state.PhysIfaceName),
		},
		Down: []string{
			fmt.Sprintf("ip route del %s dev %s", state.GatewayIP, state.PhysIfaceName),
		},
	})

	jobs = append(jobs, server.NetworkJob{
		Description: "add default route to routing table",
		Up: []string{
			fmt.Sprintf(
				"ip route add default via %s dev %s table %d",
				state.GatewayIP,
				state.PhysIfaceName,
				state.RouteTableID,
			),
		},
		Down: []string{
			fmt.Sprintf("ip route del default table %d", state.RouteTableID),
		},
	})

	jobs = append(jobs, server.NetworkJob{
		Description: "add policy routing rule",
		Up: []string{
			fmt.Sprintf(
				"ip rule add from %s lookup %d",
				state.PhysIfaceIP,
				state.RouteTableID,
			),
		},
		Down: []string{
			fmt.Sprintf(
				"ip rule del from %s lookup %d",
				state.PhysIfaceIP,
				state.RouteTableID,
			),
		},
	})

	cidrJob := server.NetworkJob{Description: "add CIDR routes via TUN"}
	for _, t := range state.RouteTargetCIDRs {
		cidrJob.Up = append(
			cidrJob.Up,
			fmt.Sprintf("ip route add %s dev %s", t, state.TUNName),
		)
		cidrJob.Down = append(
			cidrJob.Down,
			fmt.Sprintf("ip route del %s dev %s", t, state.TUNName),
		)
	}
	// Reverse Down so routes are deleted in LIFO order.
	for i, j := 0, len(cidrJob.Down)-1; i < j; i, j = i+1, j-1 {
		cidrJob.Down[i], cidrJob.Down[j] = cidrJob.Down[j], cidrJob.Down[i]
	}
	jobs = append(jobs, cidrJob)

	return jobs
}

func saveState(jobs []server.NetworkJob) error {
	type state struct {
		Jobs      []server.NetworkJob `json:"jobs"`
		CreatedAt time.Time           `json:"createdAt"`
	}
	data, err := json.MarshalIndent(state{Jobs: jobs, CreatedAt: time.Now()}, "", "  ")
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

// tunSystemNetworkLinux implements TUNSystemNetwork for Linux
type tunSystemNetworkLinux struct {
	logger       zerolog.Logger
	tunDevice    tun.Device
	defaultRoute *netutil.Route
}

// NewTUNSystemNetwork creates a new TUNSystemNetwork for TUN mode on Linux
// fibID is ignored on Linux (FreeBSD-specific)
func NewTUNSystemNetwork(
	logger zerolog.Logger,
	defaultRoute *netutil.Route,
	fibID int,
) (TUNSystemNetwork, error) {
	dev, err := createTunDevice()
	if err != nil {
		return nil, err
	}

	return &tunSystemNetworkLinux{
		logger:       logger,
		tunDevice:    dev,
		defaultRoute: defaultRoute,
	}, nil
}

func (n *tunSystemNetworkLinux) TunDevice() tun.Device {
	return n.tunDevice
}

func (n *tunSystemNetworkLinux) DefaultRoute() *netutil.Route {
	return n.defaultRoute
}

func (n *tunSystemNetworkLinux) FIBID() int {
	return 1
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

	dialer.Control = func(network, address string, c syscall.RawConn) error {
		var sockErr error
		err := c.Control(func(fd uintptr) {
			sockErr = syscall.SetsockoptString(
				int(fd),
				syscall.SOL_SOCKET,
				syscall.SO_BINDTODEVICE,
				n.defaultRoute.Iface.Name,
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

	return nil
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
