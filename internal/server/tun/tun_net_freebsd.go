//go:build freebsd

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
	"github.com/xvzc/spoofdpi/internal/executil"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/server"
	"golang.zx2c4.com/wireguard/tun"
)

const stateFile = "/tmp/spoofdpi.freebsd.tun.state"

type tunStateFreeBSD struct {
	FIBID            int       `json:"fibID"`
	GatewayIP        string    `json:"gatewayIP"`
	PhysIfaceName    string    `json:"physIfaceName"`
	PhysIfaceCIDR    string    `json:"physifaceCIDR"`
	TUNName          string    `json:"tunName"`
	TunLocalIP       string    `json:"tunLocalIP"`
	TunRemoteIP      string    `json:"tunRemoteIP"`
	RouteTargetCIDRs []string  `json:"routeTargetCIDRs"`
	CreatedAt        time.Time `json:"createdAt"`
}

func createTunDevice() (tun.Device, error) {
	return tun.CreateTUN("tun-spoofdpi", 1500)
}

func createState(sysNet TUNSystemNetwork) (*tunStateFreeBSD, error) {
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

	return &tunStateFreeBSD{ //exhaustruct:enforce
		FIBID:            sysNet.FIBID(),
		GatewayIP:        sysNet.DefaultRoute().Gateway.String(),
		PhysIfaceName:    sysNet.DefaultRoute().Iface.Name,
		PhysIfaceCIDR:    physIfaceCIDR,
		TUNName:          tunName,
		TunLocalIP:       tunLocalIP,
		TunRemoteIP:      tunRemoteIP,
		RouteTargetCIDRs: routeTargetCIDRs,
		CreatedAt:        time.Now(),
	}, nil
}

func buildJobs(state *tunStateFreeBSD) []server.NetworkJob {
	var jobs []server.NetworkJob

	jobs = append(jobs, server.NetworkJob{
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
	})

	jobs = append(jobs, server.NetworkJob{
		Description: "add FIB subnet route",
		Up: []string{
			fmt.Sprintf(
				"route add -net %s -iface %s -fib %d",
				state.PhysIfaceCIDR,
				state.PhysIfaceName,
				state.FIBID,
			),
		},
		Down: []string{
			fmt.Sprintf(
				"route delete -net %s -iface %s -fib %d",
				state.PhysIfaceCIDR,
				state.PhysIfaceName,
				state.FIBID,
			),
		},
	})

	jobs = append(jobs, server.NetworkJob{
		Description: "add FIB default route",
		Up: []string{
			fmt.Sprintf("route add default %s -fib %d", state.GatewayIP, state.FIBID),
		},
		Down: []string{fmt.Sprintf("route delete default -fib %d", state.FIBID)},
	})

	cidrJob := server.NetworkJob{Description: "add CIDR routes via TUN"}
	for _, t := range state.RouteTargetCIDRs {
		cidrJob.Up = append(
			cidrJob.Up,
			fmt.Sprintf("route -n add -net %s -interface %s", t, state.TUNName),
		)
		cidrJob.Down = append(
			cidrJob.Down,
			fmt.Sprintf("route -n delete -net %s -interface %s", t, state.TUNName),
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
