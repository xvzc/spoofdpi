//go:build linux

package tun

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/route"
	"golang.org/x/sys/unix"
)

// The server.NetworkAction types below change the network configuration
// over netlink. Their String reads as the `ip` command that does the same.

// addressAction adds addr to the link named dev, or deletes it.
type addressAction struct {
	add  bool
	addr route.InterfaceAddr
	dev  string
}

func (a addressAction) Run() error {
	if a.add {
		return route.AddAddress(a.addr)
	}
	return route.DeleteAddress(a.addr)
}

func (a addressAction) String() string {
	verb := "del"
	if a.add {
		verb = "add"
	}
	s := fmt.Sprintf("ip addr %s %s", verb, a.addr.Local)
	if a.addr.Peer.IsValid() {
		s += fmt.Sprintf(" peer %s", a.addr.Peer)
	}
	if a.addr.PrefixLen != a.addr.Local.BitLen() {
		s += fmt.Sprintf("/%d", a.addr.PrefixLen)
	}
	return s + " dev " + a.dev
}

// linkAction sets the link with index, named dev, up or down.
type linkAction struct {
	up    bool
	index int
	dev   string
}

func (a linkAction) Run() error {
	if a.up {
		return route.SetLinkUp(a.index)
	}
	return route.SetLinkDown(a.index)
}

func (a linkAction) String() string {
	state := "down"
	if a.up {
		state = "up"
	}
	return fmt.Sprintf("ip link set dev %s %s", a.dev, state)
}

// routeAction adds entry, whose output link is named dev, or deletes it.
type routeAction struct {
	add   bool
	entry route.RouteEntry
	dev   string
}

func (a routeAction) Run() error {
	if a.add {
		return route.AddRoute(a.entry)
	}
	return route.DeleteRoute(a.entry)
}

func (a routeAction) String() string {
	verb := "del"
	if a.add {
		verb = "add"
	}
	return ipRouteCommand(verb, a.entry, a.dev)
}

// ruleAction adds rule, or deletes it.
type ruleAction struct {
	add  bool
	rule route.Rule
}

func (a ruleAction) Run() error {
	if a.add {
		return route.AddRule(a.rule)
	}
	return route.DeleteRule(a.rule)
}

func (a ruleAction) String() string {
	verb := "del"
	if a.add {
		verb = "add"
	}
	return ipRuleCommand(verb, a.rule)
}

// systemNetlink is the captureNetlink of the host.
type systemNetlink struct{}

func (systemNetlink) TUNIndex() (int, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return 0, fmt.Errorf("list interfaces: %w", err)
	}
	for _, iface := range ifaces {
		if iface.Name == linuxTUNName {
			return iface.Index, nil
		}
	}
	return 0, nil
}

// TUNPersistent reads the TUN's flags from sysfs. sysfs shows the
// interfaces of the network namespace that mounted it, not of the caller's,
// so from another namespace the file may be missing or another interface's.
// A failed read leaves the TUN taken as alive, which removes nothing.
func (systemNetlink) TUNPersistent() (bool, error) {
	b, err := os.ReadFile("/sys/class/net/" + linuxTUNName + "/tun_flags")
	if err != nil {
		return false, err
	}
	return tunFlagsPersistent(string(b))
}

// tunFlagsPersistent reports whether flags, the content of a TUN's
// tun_flags sysfs file such as "0x1002", has IFF_PERSIST set.
func tunFlagsPersistent(flags string) (bool, error) {
	v, err := strconv.ParseUint(strings.TrimSpace(flags), 0, 32)
	if err != nil {
		return false, fmt.Errorf("parse tun_flags %q: %w", flags, err)
	}
	return v&unix.IFF_PERSIST != 0, nil
}

func (systemNetlink) Rules(fam netutil.Family) ([]route.Rule, error) {
	rules, err := route.Rules(fam)
	if dumpUnsupported(err) {
		return nil, nil
	}
	return rules, err
}

func (systemNetlink) Routes(fam netutil.Family) ([]route.RouteEntry, error) {
	routes, err := route.Routes(fam)
	if dumpUnsupported(err) {
		return nil, nil
	}
	return routes, err
}

func (systemNetlink) InterfaceAddrs() (map[int][]netip.Addr, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}
	addrs := make(map[int][]netip.Addr)
	for _, iface := range ifaces {
		ifAddrs, err := iface.Addrs()
		if err != nil {
			return nil, fmt.Errorf("addresses of %s: %w", iface.Name, err)
		}
		for _, a := range ifAddrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(ipnet.IP); ok {
					addrs[iface.Index] = append(addrs[iface.Index], ip.Unmap())
				}
			}
		}
	}
	return addrs, nil
}

func (systemNetlink) DeleteRule(r route.Rule) error {
	return route.DeleteRule(r)
}

func (systemNetlink) DeleteRoute(e route.RouteEntry) error {
	return route.DeleteRoute(e)
}

// dumpUnsupported reports whether err is the kernel refusing a dump
// because it lacks the family, or, for rules, policy routing
// (CONFIG_IP_MULTIPLE_TABLES), which leaves nothing to dump.
func dumpUnsupported(err error) bool {
	return errors.Is(err, syscall.EAFNOSUPPORT)
}
