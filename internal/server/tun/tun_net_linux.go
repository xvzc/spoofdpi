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
	"github.com/xvzc/spoofdpi/internal/route"
	"github.com/xvzc/spoofdpi/internal/server"
	"golang.zx2c4.com/wireguard/tun"
)

const StateFile = "/tmp/spoofdpi.linux.tun.state"

// egressFwmark marks every socket TUN mode sends through the physical
// interface, so the capture rule passes them by. It is matched exactly and
// avoids the bits that kube-proxy (0x4000, 0x8000), Cilium (0x0f00), Calico
// (0xffff0000) and Tailscale (0xff0000) use.
const egressFwmark = 0x30d5

// ipv6CaptureGroup is the server.NetworkJob group of the IPv6 jobs.
const ipv6CaptureGroup = "ipv6-capture"

type tunNetworkInfoLinux struct {
	// RouteTableID is the egress table, whose default route leaves through
	// the physical interface.
	RouteTableID int
	// CaptureTableID is the table whose routes lead into the TUN.
	CaptureTableID int
	// GatewayIP is empty when the default route has no gateway.
	GatewayIP     string
	TUNName       string
	PhysIfaceName string
	PhysIfaceIP   string
	TunLocalIP    string
	TunRemoteIP   string
	// MainRulePref, FromRulePref and CaptureRulePref are the prefs of the
	// IPv4 rules, in ascending order.
	MainRulePref    int
	FromRulePref    int
	CaptureRulePref int
	// IPv6MainRulePref and IPv6CaptureRulePref are the prefs of the IPv6
	// rules. They are 0 when IPv6 is not routed into the TUN.
	IPv6MainRulePref    int
	IPv6CaptureRulePref int
	IPv6Enabled         bool
	HasIPv6Egress       bool
	TunIPv6Disabled     bool
}

// routeTableIDs holds the egress and the capture table IDs.
type routeTableIDs struct {
	egress  int
	capture int
}

// allocateTableIDs allocates the table IDs once per process. Every call
// returns the result of the first one, error included.
var allocateTableIDs = sync.OnceValues(func() (routeTableIDs, error) {
	egress, capture, err := findAvailableTableIDs()
	return routeTableIDs{egress: egress, capture: capture}, err
})

func createTunDevice() (tun.Device, error) {
	return tun.CreateTUN("tun-spoofdpi", 1500)
}

func collectNetworkInfo(sysNet *tunSystemNetworkLinux) (*tunNetworkInfoLinux, error) {
	tunName, err := sysNet.TunDevice().Name()
	if err != nil {
		return nil, fmt.Errorf("failed to get tunName: %w", err)
	}
	tableIDs, err := allocateTableIDs()
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

	ruleOut, err := executil.Command("ip rule show")
	if err != nil {
		return nil, fmt.Errorf("failed to list IPv4 rules: %w", err)
	}
	ipv4Prefs, ahead, err := freeRulePrefs(ruleOut, 3)
	if err != nil {
		return nil, fmt.Errorf("failed to choose IPv4 rule prefs: %w", err)
	}
	warnRulesAhead(sysNet.logger, "IPv4", ahead)

	// Runs before the TUN routes exist, so it sees the system's own route.
	_, hasIPv6Egress := route.IPv6Egress()
	tunIPv6Disabled := ipv6Disabled(
		fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/disable_ipv6", tunName),
	)

	var ipv6Prefs []int
	if sysNet.ipv6Enabled && hasIPv6Egress && !tunIPv6Disabled {
		ipv6Prefs = ipv6RulePrefs(sysNet.logger)
	}
	prefs := assignRulePrefs(ipv4Prefs, ipv6Prefs)

	return &tunNetworkInfoLinux{ //exhaustruct:enforce
		RouteTableID:        tableIDs.egress,
		CaptureTableID:      tableIDs.capture,
		GatewayIP:           gateway,
		TUNName:             tunName,
		PhysIfaceName:       physIfaceName,
		PhysIfaceIP:         physIfaceIP,
		TunLocalIP:          tunLocalIP,
		TunRemoteIP:         tunRemoteIP,
		MainRulePref:        prefs.main,
		FromRulePref:        prefs.from,
		CaptureRulePref:     prefs.capture,
		IPv6MainRulePref:    prefs.ipv6Main,
		IPv6CaptureRulePref: prefs.ipv6Capture,
		IPv6Enabled:         sysNet.ipv6Enabled,
		HasIPv6Egress:       hasIPv6Egress,
		TunIPv6Disabled:     tunIPv6Disabled,
	}, nil
}

// ipv6RulePrefs returns the two prefs of the IPv6 rules, or nil, with a
// warning, when they cannot be chosen. IPv6 is optional in TUN mode, so
// this does not fail it.
func ipv6RulePrefs(logger zerolog.Logger) []int {
	out, err := executil.Command("ip -6 rule show")
	if err != nil {
		logger.Warn().
			Err(err).
			Msg("failed to list IPv6 rules; IPv6 is not routed into the TUN")
		return nil
	}
	prefs, ahead, err := freeRulePrefs(out, 2)
	if err != nil {
		logger.Warn().
			Err(err).
			Msg("failed to choose IPv6 rule prefs; IPv6 is not routed into the TUN")
		return nil
	}
	warnRulesAhead(logger, "IPv6", ahead)
	return prefs
}

// warnRulesAhead warns that TUN mode's rules come before the rules ahead,
// which were installed earlier and would otherwise come first.
func warnRulesAhead(logger zerolog.Logger, family string, ahead []string) {
	if len(ahead) == 0 {
		return
	}
	logger.Warn().
		Strs("rules", ahead).
		Msgf("no room for TUN mode's %s rules after the existing ones; "+
			"they are placed before or among these rules", family)
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
//
// The main table is left untouched. Unmarked traffic is captured by a rule
// that looks up the capture table, whose default route leads into the TUN.
// A rule before it looks up main with its default route suppressed, so the
// more specific routes in main, such as the local subnets, still win.
// Sockets marked with egressFwmark skip the capture rule and leave through
// the egress table.
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
			Description: "add gateway host route to egress table",
			Apply: fmt.Sprintf(
				"ip route add %s dev %s table %d",
				info.GatewayIP,
				info.PhysIfaceName,
				info.RouteTableID,
			),
			Reset: fmt.Sprintf(
				"ip route del %s dev %s table %d",
				info.GatewayIP,
				info.PhysIfaceName,
				info.RouteTableID,
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
		Description: "add default route to capture table",
		Apply: fmt.Sprintf(
			"ip route add default dev %s table %d",
			info.TUNName,
			info.CaptureTableID,
		),
		Reset: fmt.Sprintf(
			"ip route del default dev %s table %d",
			info.TUNName,
			info.CaptureTableID,
		),
	})

	jobs = append(jobs, server.NetworkJob{
		Description: "add rule for the main table without its default route " +
			"(needs suppress_prefixlength: iproute2 and Linux 3.12+)",
		Apply: fmt.Sprintf(
			"ip rule add pref %d lookup main suppress_prefixlength 0",
			info.MainRulePref,
		),
		Reset: fmt.Sprintf(
			"ip rule del pref %d lookup main suppress_prefixlength 0",
			info.MainRulePref,
		),
	})

	jobs = append(jobs, server.NetworkJob{
		Description: "add policy routing rule",
		Apply: fmt.Sprintf(
			"ip rule add pref %d from %s lookup %d",
			info.FromRulePref,
			info.PhysIfaceIP,
			info.RouteTableID,
		),
		Reset: fmt.Sprintf(
			"ip rule del pref %d from %s lookup %d",
			info.FromRulePref,
			info.PhysIfaceIP,
			info.RouteTableID,
		),
	})

	// Capture starts with this rule, so it goes last.
	jobs = append(jobs, server.NetworkJob{
		Description: "add capture rule for unmarked traffic",
		Apply: fmt.Sprintf(
			"ip rule add pref %d not fwmark 0x%x lookup %d",
			info.CaptureRulePref,
			egressFwmark,
			info.CaptureTableID,
		),
		Reset: fmt.Sprintf(
			"ip rule del pref %d not fwmark 0x%x lookup %d",
			info.CaptureRulePref,
			egressFwmark,
			info.CaptureTableID,
		),
	})

	// Without --ipv6, IPv6 is left to the system's routes. With it, the TUN
	// server refuses IPv6, so applications fall back to IPv4. The jobs are
	// optional: IPv4 keeps working without them. They form a group, so a
	// failed job skips the later ones: the capture rule must not route IPv6
	// into the TUN without the route that captures it, or ahead of main's
	// specific routes. TUN mode never dials IPv6, so IPv6 needs no egress
	// table.
	if info.IPv6Enabled && info.HasIPv6Egress && !info.TunIPv6Disabled &&
		info.IPv6MainRulePref != 0 {
		jobs = append(jobs, server.NetworkJob{
			Description: fmt.Sprintf(
				"add IPv6 route %s to capture table",
				ipv6CaptureCIDR,
			),
			Apply: fmt.Sprintf(
				"ip -6 route add %s dev %s table %d",
				ipv6CaptureCIDR,
				info.TUNName,
				info.CaptureTableID,
			),
			Reset: fmt.Sprintf(
				"ip -6 route del %s dev %s table %d",
				ipv6CaptureCIDR,
				info.TUNName,
				info.CaptureTableID,
			),
			Optional: true,
			Group:    ipv6CaptureGroup,
		})

		jobs = append(jobs, server.NetworkJob{
			Description: "add IPv6 rule for the main table without its default " +
				"route (needs suppress_prefixlength: iproute2 and Linux 3.12+)",
			Apply: fmt.Sprintf(
				"ip -6 rule add pref %d lookup main suppress_prefixlength 0",
				info.IPv6MainRulePref,
			),
			Reset: fmt.Sprintf(
				"ip -6 rule del pref %d lookup main suppress_prefixlength 0",
				info.IPv6MainRulePref,
			),
			Optional: true,
			Group:    ipv6CaptureGroup,
		})

		jobs = append(jobs, server.NetworkJob{
			Description: "add IPv6 capture rule for unmarked traffic",
			Apply: fmt.Sprintf(
				"ip -6 rule add pref %d not fwmark 0x%x lookup %d",
				info.IPv6CaptureRulePref,
				egressFwmark,
				info.CaptureTableID,
			),
			Reset: fmt.Sprintf(
				"ip -6 rule del pref %d not fwmark 0x%x lookup %d",
				info.IPv6CaptureRulePref,
				egressFwmark,
				info.CaptureTableID,
			),
			Optional: true,
			Group:    ipv6CaptureGroup,
			Warning:  ipv6RejectWarning,
		})
	}

	return jobs
}

// tunSystemNetworkLinux implements TUNSystemNetwork for Linux
type tunSystemNetworkLinux struct {
	logger       zerolog.Logger
	tunDevice    tun.Device
	defaultRoute *route.Route
	ipv6Enabled  bool
}

// NewTUNSystemNetwork creates a new TUNSystemNetwork for TUN mode on Linux
// fibID is ignored on Linux (FreeBSD-specific). IPv6 is routed into the TUN
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
// physical interface of rt with SO_BINDTODEVICE and marks it with
// egressFwmark through SO_MARK, as TUN mode needs: its capture rule would
// otherwise carry the traffic into the TUN, and the mark is what lets the
// socket pass that rule. fibID is not used on Linux. It returns nil when
// rt has no interface. BindDialer pins the dialed connections with it, and
// TUN mode pins the raw sockets of fake packets with it too, so the two
// cannot diverge.
func EgressControl(
	rt *route.Route,
	fibID int,
) func(network, address string, c syscall.RawConn) error {
	if rt == nil || rt.Iface.Name == "" {
		return nil
	}
	name := rt.Iface.Name
	return func(_, _ string, c syscall.RawConn) error {
		var bindErr, markErr error
		err := c.Control(func(fd uintptr) {
			bindErr = syscall.SetsockoptString(
				int(fd),
				syscall.SOL_SOCKET,
				syscall.SO_BINDTODEVICE,
				name,
			)
			if bindErr != nil {
				return
			}
			markErr = syscall.SetsockoptInt(
				int(fd),
				syscall.SOL_SOCKET,
				syscall.SO_MARK,
				egressFwmark,
			)
		})
		if err != nil {
			return fmt.Errorf("failed to control socket: %w", err)
		}
		if bindErr != nil {
			return fmt.Errorf("failed to set SO_BINDTODEVICE: %w", bindErr)
		}
		if markErr != nil {
			return fmt.Errorf("failed to set SO_MARK: %w", markErr)
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

// findAvailableTableIDs returns two distinct unused table IDs, the egress
// table first.
func findAvailableTableIDs() (egress, capture int, err error) {
	var ids []int
	for id := 200; id <= 250 && len(ids) < 2; id++ {
		if tableAvailable(id) {
			ids = append(ids, id)
		}
	}
	if len(ids) < 2 {
		return 0, 0, fmt.Errorf("no two available routing table IDs in range 200-250")
	}

	return ids[0], ids[1], nil
}

// tableAvailable reports whether table id holds no IPv4 or IPv6 route and
// no rule refers to it.
func tableAvailable(id int) bool {
	out, err := executil.Commandf("ip route show table %d", id)
	if err != nil {
		return true
	}
	if len(out) > 0 {
		return false
	}

	// A failed command prints its error, not rules: only the output of a
	// command that succeeded counts. The capture table also holds an IPv6
	// route and IPv6 rules; without IPv6 the -6 commands fail, and there
	// is nothing to collide with.
	for _, cmd := range []string{
		"ip rule show table %d",
		"ip rule show lookup %d",
		"ip -6 route show table %d",
		"ip -6 rule show table %d",
		"ip -6 rule show lookup %d",
	} {
		if out, err := executil.Commandf(cmd, id); err == nil && len(out) > 0 {
			return false
		}
	}
	return true
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
