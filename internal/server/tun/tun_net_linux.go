//go:build linux

package tun

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/route"
	"github.com/xvzc/spoofdpi/internal/server"
	"golang.zx2c4.com/wireguard/tun"
)

// ipv6CaptureGroup is the server.NetworkJob group of the IPv6 jobs.
const ipv6CaptureGroup = "ipv6-capture"

type tunNetworkInfoLinux struct {
	// CaptureTableID is the table whose routes lead into the TUN.
	CaptureTableID uint32
	TUNName        string
	TUNIndex       int
	PhysIfaceIP    netip.Addr
	TunLocalIP     netip.Addr
	TunRemoteIP    netip.Addr
	// MainRulePref, FromRulePref and CaptureRulePref are the prefs of the
	// IPv4 rules, in ascending order and consecutive.
	MainRulePref    uint32
	FromRulePref    uint32
	CaptureRulePref uint32
	// IPv6MainRulePref and IPv6CaptureRulePref are the consecutive prefs of
	// the IPv6 rules. They are 0 when IPv6 is not routed into the TUN.
	IPv6MainRulePref    uint32
	IPv6CaptureRulePref uint32
	IPv6Enabled         bool
	HasIPv6Egress       bool
	TunIPv6Disabled     bool
}

// allocateCaptureTableID allocates the capture table ID once per process.
// Every call returns the result of the first one, error included.
var allocateCaptureTableID = sync.OnceValues(findAvailableTableID)

func createTunDevice() (tun.Device, error) {
	return tun.CreateTUN(linuxTUNName, 1500)
}

func collectNetworkInfo(sysNet *tunSystemNetworkLinux) (*tunNetworkInfoLinux, error) {
	tunName, err := sysNet.TunDevice().Name()
	if err != nil {
		return nil, fmt.Errorf("failed to get tunName: %w", err)
	}
	tunIface, err := net.InterfaceByName(tunName)
	if err != nil {
		return nil, fmt.Errorf("failed to look up interface %s: %w", tunName, err)
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

	tunLocalIP, err := addrInCIDR(cidr, 1)
	if err != nil {
		return nil, err
	}
	tunRemoteIP, err := addrInCIDR(cidr, 2)
	if err != nil {
		return nil, err
	}

	ipv4Rules, err := route.Rules(netutil.FamilyV4)
	if err != nil {
		return nil, fmt.Errorf("failed to list IPv4 rules: %w", err)
	}
	ipv4Prefs, ahead, err := freeRulePrefs(ipv4Rules, 3)
	if err != nil {
		return nil, fmt.Errorf("failed to choose IPv4 rule prefs: %w", err)
	}
	warnRulesAhead(sysNet.logger, "IPv4", ahead)

	// Runs before the TUN routes exist, so it sees the system's own route.
	_, hasIPv6Egress := route.IPv6Egress()
	tunIPv6Disabled := ipv6Disabled(
		fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/disable_ipv6", tunName),
	)

	var ipv6Prefs []uint32
	if sysNet.ipv6Enabled && hasIPv6Egress && !tunIPv6Disabled {
		ipv6Prefs = ipv6RulePrefs(sysNet.logger)
	}
	prefs := assignRulePrefs(ipv4Prefs, ipv6Prefs)

	return &tunNetworkInfoLinux{ //exhaustruct:enforce
		CaptureTableID:      captureTableID,
		TUNName:             tunName,
		TUNIndex:            tunIface.Index,
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

// addrInCIDR returns the nth address of cidr.
func addrInCIDR(cidr string, n int) (netip.Addr, error) {
	s, err := route.AddrInCIDR(cidr, n)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("failed to get %dth ip in %s: %w", n, cidr, err)
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("failed to get %dth ip in %s: %w", n, cidr, err)
	}
	return addr, nil
}

// ipv6RulePrefs returns the two prefs of the IPv6 rules, or nil, with a
// warning, when they cannot be chosen. IPv6 is optional in TUN mode, so
// this does not fail it.
func ipv6RulePrefs(logger zerolog.Logger) []uint32 {
	rules, err := route.Rules(netutil.FamilyV6)
	if err != nil {
		logger.Warn().
			Err(err).
			Msg("failed to list IPv6 rules; IPv6 is not routed into the TUN")
		return nil
	}
	prefs, ahead, err := freeRulePrefs(rules, 2)
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
func warnRulesAhead(logger zerolog.Logger, family string, ahead []route.Rule) {
	if len(ahead) == 0 {
		return
	}
	lines := make([]string, 0, len(ahead))
	for _, r := range ahead {
		lines = append(lines, r.String())
	}
	logger.Warn().
		Strs("rules", lines).
		Msgf("no room for TUN mode's %s rules after the existing ones; "+
			"they are placed before these rules", family)
}

func (n *tunSystemNetworkLinux) BuildJobs() ([]server.NetworkJob, error) {
	err := checkRuleProtocol(
		func() ([]route.Rule, error) { return route.Rules(netutil.FamilyV4) },
		route.RuleProtocolSupported,
		kernelRelease,
	)
	if err != nil {
		return nil, err
	}
	info, err := collectNetworkInfo(n)
	if err != nil {
		return nil, err
	}
	recordThisRun(info)
	return buildJobs(info), nil
}

// checkRuleProtocol returns an error when the kernel cannot hold TUN
// mode's rules as tagged rules: it has no policy routing, shows no IPv4
// rule, or drops the protocol tag of rules, as kernels before 4.17 do
// without an error, so that the next start could not tell TUN mode's rules
// from others to remove them after a crash. rules dumps the IPv4 rules,
// supported is route.RuleProtocolSupported, and release returns the
// kernel's version for the errors.
func checkRuleProtocol(
	rules func() ([]route.Rule, error),
	supported func() (bool, error),
	release func() string,
) error {
	dump, err := rules()
	switch {
	case errors.Is(err, syscall.EAFNOSUPPORT):
		return fmt.Errorf(
			"TUN mode needs policy routing (CONFIG_IP_MULTIPLE_TABLES), "+
				"which kernel %s lacks: %w",
			release(),
			err,
		)
	case err != nil:
		return fmt.Errorf("failed to list IPv4 rules: %w", err)
	case len(dump) == 0:
		return fmt.Errorf(
			"TUN mode needs the kernel's IPv4 rules, such as "+
				"\"from all lookup main\", but kernel %s shows none",
			release(),
		)
	}
	ok, err := supported()
	if err != nil {
		return fmt.Errorf("failed to check the kernel's rule protocol support: %w", err)
	}
	if !ok {
		return fmt.Errorf(
			"TUN mode's network configuration needs Linux 4.17 or later, "+
				"which keeps the protocol tag of routing rules; this kernel is %s",
			release(),
		)
	}
	return nil
}

// kernelRelease returns the kernel's release, such as 6.18.0, or "unknown".
func kernelRelease() string {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(b))
}

// buildJobs returns the jobs that route traffic into the TUN described by
// info. Every rule and route they add carries captureProtocol, so a later
// run can find them after a crash (see CleanLeftovers).
//
// The main table is left untouched. Unmarked traffic is captured by a rule
// that looks up the capture table, whose default route leads into the TUN.
// A rule before it looks up main with its default route suppressed, so the
// more specific routes in main, such as the local subnets, still win.
// The capture rule matches only packets whose mark is 0, so packets that
// carry any mark skip it and follow the system's other rules. That covers
// sockets marked with egressFwmark, which leave by the main table's routes,
// and the tunnel packets of a VPN such as wg-quick, which marks its own.
//
// The capture rule, the anchor of the leftover search, goes first: while
// the capture table is empty, it captures nothing. The rules before it
// follow, and capture starts with the route in the capture table, last.
// A run that crashes halfway so leaves the anchor behind with the rest.
func buildJobs(info *tunNetworkInfoLinux) []server.NetworkJob {
	var jobs []server.NetworkJob
	table := info.CaptureTableID

	addr := route.InterfaceAddr{
		Index:     info.TUNIndex,
		Local:     info.TunLocalIP,
		Peer:      info.TunRemoteIP,
		PrefixLen: info.TunRemoteIP.BitLen(),
	}
	jobs = append(jobs, server.NetworkJob{
		Description: "configure TUN interface address",
		Apply:       addressAction{add: true, addr: addr, dev: info.TUNName},
		Reset:       addressAction{add: false, addr: addr, dev: info.TUNName},
	})

	jobs = append(jobs, server.NetworkJob{
		Description: "bring TUN interface up",
		Apply:       linkAction{up: true, index: info.TUNIndex, dev: info.TUNName},
		Reset:       linkAction{up: false, index: info.TUNIndex, dev: info.TUNName},
	})

	jobs = append(jobs, ruleJob(
		"add capture rule for unmarked traffic",
		captureRule(netutil.FamilyV4, info.CaptureRulePref, table),
	))

	jobs = append(jobs, ruleJob(
		"add rule for the main table without its default route",
		mainLookupRule(netutil.FamilyV4, info.MainRulePref),
	))

	// Traffic from the physical interface's address looks up main in full,
	// before the capture rule. spoofdpi's own sockets carry the mark and
	// skip the capture rule anyway, but the reverse-path lookup of their
	// replies does not: it has mark 0 and the reply's destination, the
	// physical address, as its source. Under strict reverse-path filtering,
	// such as NixOS's nftables "fib saddr . mark . iif", that lookup would
	// otherwise resolve to the TUN, and the replies would be dropped.
	jobs = append(jobs, ruleJob(
		"add policy routing rule",
		fromRule(info.FromRulePref, info.PhysIfaceIP),
	))

	// Capture starts with this route, so it goes last.
	jobs = append(jobs, routeJob(
		"add default route to capture table",
		captureRoute(netutil.FamilyV4, table, info.TUNIndex),
		info.TUNName,
	))

	// Without --ipv6, IPv6 is left to the system's routes. With it, the TUN
	// server refuses IPv6, so applications fall back to IPv4. The jobs are
	// optional: IPv4 keeps working without them. They form a group, so a
	// failed job skips the later ones: the route that starts capture must
	// not be added without the rule that keeps main's specific routes ahead
	// of it. TUN mode never dials IPv6, so IPv6 needs no rule for traffic
	// from the physical interface.
	if info.IPv6Enabled && info.HasIPv6Egress && !info.TunIPv6Disabled &&
		info.IPv6MainRulePref != 0 {
		ipv6Capture := ruleJob(
			"add IPv6 capture rule for unmarked traffic",
			captureRule(netutil.FamilyV6, info.IPv6CaptureRulePref, table),
		)
		ipv6Capture.Optional, ipv6Capture.Group = true, ipv6CaptureGroup
		jobs = append(jobs, ipv6Capture)

		ipv6Main := ruleJob(
			"add IPv6 rule for the main table without its default route",
			mainLookupRule(netutil.FamilyV6, info.IPv6MainRulePref),
		)
		ipv6Main.Optional, ipv6Main.Group = true, ipv6CaptureGroup
		jobs = append(jobs, ipv6Main)

		ipv6Route := routeJob(
			fmt.Sprintf("add IPv6 route %s to capture table", ipv6CaptureCIDR),
			captureRoute(netutil.FamilyV6, table, info.TUNIndex),
			info.TUNName,
		)
		ipv6Route.Optional, ipv6Route.Group = true, ipv6CaptureGroup
		ipv6Route.Warning = ipv6RejectWarning
		jobs = append(jobs, ipv6Route)
	}

	return jobs
}

// ruleJob returns the job that adds r and deletes it on reset.
func ruleJob(description string, r route.Rule) server.NetworkJob {
	return server.NetworkJob{
		Description: description,
		Apply:       ruleAction{add: true, rule: r},
		Reset:       ruleAction{add: false, rule: r},
	}
}

// routeJob returns the job that adds e, whose output link is named dev,
// and deletes it on reset.
func routeJob(description string, e route.RouteEntry, dev string) server.NetworkJob {
	return server.NetworkJob{
		Description: description,
		Apply:       routeAction{add: true, entry: e, dev: dev},
		Reset:       routeAction{add: false, entry: e, dev: dev},
	}
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

// findAvailableTableID returns a capture table ID that holds no IPv4 or
// IPv6 route and that no rule refers to.
func findAvailableTableID() (uint32, error) {
	nl := systemNetlink{}
	var rules []route.Rule
	var routes []route.RouteEntry
	for _, fam := range captureFamilies {
		famRules, err := nl.Rules(fam)
		if err != nil {
			return 0, err
		}
		famRoutes, err := nl.Routes(fam)
		if err != nil {
			return 0, err
		}
		rules = append(rules, famRules...)
		routes = append(routes, famRoutes...)
	}
	return freeCaptureTable(rules, routes)
}

// getInterfaceIP returns the first IPv4 address of the interface named
// ifaceName.
func getInterfaceIP(ifaceName string) (netip.Addr, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return netip.Addr{}, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return netip.Addr{}, err
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if ip, ok := netip.AddrFromSlice(ipnet.IP.To4()); ok {
			return ip, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("IP not found for interface %s", ifaceName)
}
