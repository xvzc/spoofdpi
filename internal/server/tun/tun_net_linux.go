//go:build linux

package tun

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/executil"
	"github.com/xvzc/spoofdpi/internal/route"
	"github.com/xvzc/spoofdpi/internal/server"
	"golang.zx2c4.com/wireguard/tun"
)

// egressFwmark marks every socket TUN mode sends through the physical
// interface, so the capture rule, which matches only unmarked packets, passes
// them by. Any nonzero mark would do; this one avoids the bits that
// kube-proxy (0x4000, 0x8000), Cilium (0x0f00), Calico (0xffff0000) and
// Tailscale (0xff0000) use.
const egressFwmark = 0x30d5

// ipv6CaptureGroup is the server.NetworkJob group of the IPv6 jobs.
const ipv6CaptureGroup = "ipv6-capture"

type tunNetworkInfoLinux struct {
	// CaptureTableID is the table whose routes lead into the TUN.
	CaptureTableID int
	TUNName        string
	PhysIfaceIP    string
	TunLocalIP     string
	TunRemoteIP    string
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

// allocateCaptureTableID allocates the capture table ID once per process.
// Every call returns the result of the first one, error included.
var allocateCaptureTableID = sync.OnceValues(findAvailableTableID)

func createTunDevice() (tun.Device, error) {
	return tun.CreateTUN("tun-spoofdpi", 1500)
}

func collectNetworkInfo(sysNet *tunSystemNetworkLinux) (*tunNetworkInfoLinux, error) {
	tunName, err := sysNet.TunDevice().Name()
	if err != nil {
		return nil, fmt.Errorf("failed to get tunName: %w", err)
	}
	captureTableID, err := allocateCaptureTableID()
	if err != nil {
		return nil, fmt.Errorf("failed to allocate routing table ID: %w", err)
	}

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
		CaptureTableID:      captureTableID,
		TUNName:             tunName,
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
// The capture rule matches only packets whose mark is 0, so packets that
// carry any mark skip it and follow the system's other rules. That covers
// sockets marked with egressFwmark, which leave by the main table's routes,
// and the tunnel packets of a VPN such as wg-quick, which marks its own.
func buildJobs(info *tunNetworkInfoLinux) []server.NetworkJob {
	var jobs []server.NetworkJob
	table := strconv.Itoa(info.CaptureTableID)

	jobs = append(jobs, server.NetworkJob{
		Description: "remove TUN interface",
		Reset:       server.CommandAction{"ip", "link", "delete", info.TUNName},
	})

	jobs = append(jobs, server.NetworkJob{
		Description: "configure TUN interface address",
		Apply: server.CommandAction{
			"ip", "addr", "add", info.TunLocalIP,
			"peer", info.TunRemoteIP, "dev", info.TUNName,
		},
		Reset: server.CommandAction{
			"ip", "addr", "del", info.TunLocalIP,
			"peer", info.TunRemoteIP, "dev", info.TUNName,
		},
	})

	jobs = append(jobs, server.NetworkJob{
		Description: "bring TUN interface up",
		Apply:       server.CommandAction{"ip", "link", "set", "dev", info.TUNName, "up"},
		Reset:       server.CommandAction{"ip", "link", "set", "dev", info.TUNName, "down"},
	})

	jobs = append(jobs, server.NetworkJob{
		Description: "add default route to capture table",
		Apply: server.CommandAction{
			"ip", "route", "add", "default", "dev", info.TUNName, "table", table,
		},
		Reset: server.CommandAction{
			"ip", "route", "del", "default", "dev", info.TUNName, "table", table,
		},
	})

	jobs = append(jobs, server.NetworkJob{
		Description: "add rule for the main table without its default route " +
			"(needs suppress_prefixlength: iproute2 and Linux 3.12+)",
		Apply: server.CommandAction{
			"ip", "rule", "add", "pref", strconv.Itoa(info.MainRulePref),
			"lookup", "main", "suppress_prefixlength", "0",
		},
		Reset: server.CommandAction{
			"ip", "rule", "del", "pref", strconv.Itoa(info.MainRulePref),
			"lookup", "main", "suppress_prefixlength", "0",
		},
	})

	// Traffic from the physical interface's address looks up main in full,
	// before the capture rule. spoofdpi's own sockets carry the mark and
	// skip the capture rule anyway, but the reverse-path lookup of their
	// replies does not: it has mark 0 and the reply's destination, the
	// physical address, as its source. Under strict reverse-path filtering,
	// such as NixOS's nftables "fib saddr . mark . iif", that lookup would
	// otherwise resolve to the TUN, and the replies would be dropped.
	jobs = append(jobs, server.NetworkJob{
		Description: "add policy routing rule",
		Apply: server.CommandAction{
			"ip", "rule", "add", "pref", strconv.Itoa(info.FromRulePref),
			"from", info.PhysIfaceIP, "lookup", "main",
		},
		Reset: server.CommandAction{
			"ip", "rule", "del", "pref", strconv.Itoa(info.FromRulePref),
			"from", info.PhysIfaceIP, "lookup", "main",
		},
	})

	// Capture starts with this rule, so it goes last.
	jobs = append(jobs, server.NetworkJob{
		Description: "add capture rule for unmarked traffic",
		Apply: server.CommandAction{
			"ip", "rule", "add", "pref", strconv.Itoa(info.CaptureRulePref),
			"fwmark", "0/0xffffffff", "lookup", table,
		},
		Reset: server.CommandAction{
			"ip", "rule", "del", "pref", strconv.Itoa(info.CaptureRulePref),
			"fwmark", "0/0xffffffff", "lookup", table,
		},
	})

	// Without --ipv6, IPv6 is left to the system's routes. With it, the TUN
	// server refuses IPv6, so applications fall back to IPv4. The jobs are
	// optional: IPv4 keeps working without them. They form a group, so a
	// failed job skips the later ones: the capture rule must not route IPv6
	// into the TUN without the route that captures it, or ahead of main's
	// specific routes. TUN mode never dials IPv6, so IPv6 needs no rule for
	// traffic from the physical interface.
	if info.IPv6Enabled && info.HasIPv6Egress && !info.TunIPv6Disabled &&
		info.IPv6MainRulePref != 0 {
		jobs = append(jobs, server.NetworkJob{
			Description: fmt.Sprintf(
				"add IPv6 route %s to capture table",
				ipv6CaptureCIDR,
			),
			Apply: server.CommandAction{
				"ip", "-6", "route", "add", ipv6CaptureCIDR,
				"dev", info.TUNName, "table", table,
			},
			Reset: server.CommandAction{
				"ip", "-6", "route", "del", ipv6CaptureCIDR,
				"dev", info.TUNName, "table", table,
			},
			Optional: true,
			Group:    ipv6CaptureGroup,
		})

		jobs = append(jobs, server.NetworkJob{
			Description: "add IPv6 rule for the main table without its default " +
				"route (needs suppress_prefixlength: iproute2 and Linux 3.12+)",
			Apply: server.CommandAction{
				"ip", "-6", "rule", "add", "pref", strconv.Itoa(info.IPv6MainRulePref),
				"lookup", "main", "suppress_prefixlength", "0",
			},
			Reset: server.CommandAction{
				"ip", "-6", "rule", "del", "pref", strconv.Itoa(info.IPv6MainRulePref),
				"lookup", "main", "suppress_prefixlength", "0",
			},
			Optional: true,
			Group:    ipv6CaptureGroup,
		})

		jobs = append(jobs, server.NetworkJob{
			Description: "add IPv6 capture rule for unmarked traffic",
			Apply: server.CommandAction{
				"ip", "-6", "rule", "add", "pref", strconv.Itoa(info.IPv6CaptureRulePref),
				"fwmark", "0/0xffffffff", "lookup", table,
			},
			Reset: server.CommandAction{
				"ip", "-6", "rule", "del", "pref", strconv.Itoa(info.IPv6CaptureRulePref),
				"fwmark", "0/0xffffffff", "lookup", table,
			},
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
// otherwise carry the traffic into the TUN, and any mark lets the socket
// pass that rule. fibID is not used on Linux. It returns nil when
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

// findAvailableTableID returns an unused table ID.
func findAvailableTableID() (int, error) {
	for id := 200; id <= 250; id++ {
		if tableAvailable(id) {
			return id, nil
		}
	}
	return 0, fmt.Errorf("no available routing table ID in range 200-250")
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
