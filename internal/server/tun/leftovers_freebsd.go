//go:build freebsd

package tun

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/netif"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/route"
	"github.com/xvzc/spoofdpi/internal/server"
	xroute "golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// CleanLeftovers removes the routes and the TUN interface that an earlier
// TUN mode run left behind when it ended without restoring them, such as on
// a crash. It runs at startup in every mode, before anything reads the
// routes, and never fails the start.
//
// A run that crashed leaves tun-spoofdpi behind, closed. The tagged routes
// into it in the main FIB go, and then the interface. The FIB of
// opts.FreeBSDFIB is spoofdpi's own, so its tagged default and subnet
// routes go too, with or without the interface. The tagged routes of that
// shape in the other FIBs, which may belong to another program, are only
// warned about, at every start until they are gone. Routes of the same shape without
// the tag are left alone, with a warning that tells how to remove them.
// Nothing is removed while another spoofdpi holds tun-spoofdpi open.
func CleanLeftovers(logger zerolog.Logger, opts CleanupOptions) {
	server.RemoveLeftovers(logger, systemLeftoverEnv().find(logger, opts.FreeBSDFIB))
}

// CheckLeftoversAfterReset warns about the routes of this run that are
// still there after ResetJobs restored the network configuration, which
// points to a bug in a job's Reset. It removes nothing.
func CheckLeftoversAfterReset(logger zerolog.Logger) {
	run, ok := thisRun()
	if !ok {
		return
	}
	server.WarnLeftoversAfterReset(logger, systemLeftoverEnv().afterReset(logger, run))
}

// runInfo identifies the network configuration of this run.
type runInfo struct {
	FIB      int
	TUNName  string
	TUNIndex int
}

var (
	currentRunMu  sync.Mutex
	currentRun    runInfo
	currentRunSet bool
)

// rememberRun keeps r for CheckLeftoversAfterReset.
func rememberRun(r runInfo) {
	currentRunMu.Lock()
	defer currentRunMu.Unlock()
	currentRun, currentRunSet = r, true
}

// thisRun returns what rememberRun kept, and false when it kept nothing.
func thisRun() (runInfo, bool) {
	currentRunMu.Lock()
	defer currentRunMu.Unlock()
	return currentRun, currentRunSet
}

// leftoverEnv is what finding and removing leftovers reads and changes in
// the system. Tests replace it.
type leftoverEnv struct {
	tunName string
	// tunOpened reports whether a process holds the tun open. It fails
	// with ENXIO when the interface does not exist.
	tunOpened func(name string) (bool, error)
	// tunIndex returns the index of the interface, 0 when it does not
	// exist, and whether it is a tun.
	tunIndex    func(name string) (index int, isTun bool, err error)
	destroy     func(name string) error
	fibCount    func() (int, error)
	dumpRoutes  func(fam netutil.Family, fib int) ([]route.TableRoute, error)
	deleteRoute func(fib int, r route.TableRoute) error
}

func systemLeftoverEnv() leftoverEnv {
	return leftoverEnv{
		tunName:   tunIfName,
		tunOpened: netif.TunOpened,
		tunIndex:  tunInterfaceIndex,
		destroy:   netif.Destroy,
		fibCount: func() (int, error) {
			n, err := unix.SysctlUint32("net.fibs")
			return int(n), err
		},
		dumpRoutes:  route.DumpRoutes,
		deleteRoute: route.DeleteRoute,
	}
}

// find returns the leftovers of the runs that crashed, as CleanLeftovers
// describes them; configuredFIB is the FIB of freebsd-fib, or 0.
func (e leftoverEnv) find(logger zerolog.Logger, configuredFIB int) []server.Leftover {
	tunIndex, live, ok := e.tunAnchor(logger)
	if live {
		logger.Info().
			Str("interface", e.tunName).
			Msg("another spoofdpi is running; leaving its network configuration alone")
		return nil
	}
	if !ok {
		return nil
	}

	var leftovers []server.Leftover
	if tunIndex > 0 {
		leftovers = append(leftovers, e.mainFIBLeftovers(logger, tunIndex, true)...)
	}
	for _, fib := range e.fibsToClean(logger, configuredFIB) {
		// Only the FIB of freebsd-fib belongs to spoofdpi alone, so only
		// there do its routes go, and only there does an untagged route of
		// the same shape point to an earlier version of spoofdpi rather than
		// to someone else. Another FIB may serve a routing daemon that uses
		// the tag too, so its tagged routes are only warned about.
		if fib == configuredFIB {
			leftovers = append(leftovers, e.fibLeftovers(logger, fib, true)...)
		} else {
			leftovers = append(leftovers, e.otherFIBLeftovers(logger, fib)...)
		}
	}
	if tunIndex > 0 {
		leftovers = append(leftovers, server.Leftover{
			Description:   fmt.Sprintf("interface %s, closed", e.tunName),
			Remove:        e.removeTun,
			ManualCommand: "ifconfig " + e.tunName + " destroy",
		})
	}
	return leftovers
}

// tunAnchor looks for the tun that a crashed run left behind. index is its
// interface index, or 0 when there is none to clean up. live is true when a
// process holds it open, which means another spoofdpi runs. ok is false when
// it cannot tell, such as when a tun does not report whether it is open,
// in which case nothing must be removed. The type of the interface is
// checked first: the open state means something for a tun only.
func (e leftoverEnv) tunAnchor(logger zerolog.Logger) (index int, live, ok bool) {
	index, isTun, err := e.tunIndex(e.tunName)
	if err != nil {
		logger.Warn().Err(err).
			Str("interface", e.tunName).
			Msg("cannot read the interface; leftovers not cleaned up")
		return 0, false, false
	}
	if index == 0 {
		return 0, false, true
	}
	if !isTun {
		logger.Warn().
			Str("interface", e.tunName).
			Msg("interface is not a tun; left alone")
		return 0, false, true
	}
	opened, err := e.tunOpened(e.tunName)
	switch {
	case errors.Is(err, unix.ENXIO):
		return 0, false, true
	case err != nil:
		logger.Warn().Err(err).
			Str("interface", e.tunName).
			Msg("cannot tell whether another spoofdpi is running; leftovers not cleaned up")
		return 0, false, false
	case opened:
		return 0, true, true
	}
	return index, false, true
}

// fibsToClean returns the FIBs other than the main one to look in: all of
// them, or only configuredFIB, when set, if their number cannot be read.
func (e leftoverEnv) fibsToClean(logger zerolog.Logger, configuredFIB int) []int {
	count, err := e.fibCount()
	if err != nil {
		logger.Warn().
			Err(err).
			Msg("cannot read net.fibs; looking only in the configured FIB")
		if configuredFIB > 0 {
			return []int{configuredFIB}
		}
		return nil
	}
	fibs := make([]int, 0, max(count-1, 0))
	for fib := 1; fib < count; fib++ {
		fibs = append(fibs, fib)
	}
	return fibs
}

// mainFIBLeftovers returns the routes of the main FIB through the tun with
// tunIndex that spoofdpi adds: the tagged ones to remove and, when
// warnUntagged is set, the untagged ones to warn about.
func (e leftoverEnv) mainFIBLeftovers(
	logger zerolog.Logger,
	tunIndex int,
	warnUntagged bool,
) []server.Leftover {
	isMainRoute := func(r route.TableRoute) bool {
		return isMainFIBRouteShape(r, tunIndex)
	}
	return slices.Concat(
		e.routeLeftovers(logger, netutil.FamilyV4, mainFIB, isMainRoute, warnUntagged),
		e.routeLeftovers(logger, netutil.FamilyV6, mainFIB, isMainRoute, warnUntagged),
	)
}

// fibLeftovers returns the default and subnet routes of fib that spoofdpi
// adds: the tagged ones to remove and, when warnUntagged is set, the
// untagged ones to warn about.
func (e leftoverEnv) fibLeftovers(
	logger zerolog.Logger,
	fib int,
	warnUntagged bool,
) []server.Leftover {
	return e.routeLeftovers(logger, netutil.FamilyV4, fib, isFIBRouteShape, warnUntagged)
}

// maxFreeBSDFIB is the largest FIB that freebsd-fib takes.
const maxFreeBSDFIB = 15

// otherFIBLeftovers returns, for fib, a FIB other than that of
// freebsd-fib, one leftover to warn about that lists the tagged routes of
// fib with the shape of spoofdpi's, or none when it has none. They are not
// removed: spoofdpi removes them from the FIB of freebsd-fib only.
func (e leftoverEnv) otherFIBLeftovers(
	logger zerolog.Logger,
	fib int,
) []server.Leftover {
	found := e.fibLeftovers(logger, fib, false)
	if len(found) == 0 {
		return nil
	}
	routes := make([]string, 0, len(found))
	commands := make([]string, 0, len(found))
	for _, l := range found {
		routes = append(routes, l.Description)
		commands = append(commands, l.ManualCommand)
	}
	hint := fmt.Sprintf("start spoofdpi once with --freebsd-fib %d to remove them", fib)
	if fib > maxFreeBSDFIB {
		hint = fmt.Sprintf(
			"remove them by hand: freebsd-fib takes 1 to %d only",
			maxFreeBSDFIB,
		)
	}
	return []server.Leftover{{
		Description: fmt.Sprintf(
			"tagged routes of fib %d with the shape of spoofdpi's (%s); %s",
			fib, strings.Join(routes, "; "), hint,
		),
		ManualCommand: strings.Join(commands, "; "),
	}}
}

// routeLeftovers returns the routes of fam in fib that have the shape
// isShape accepts: a removable leftover for each tagged one and, when
// warnUntagged is set, one to warn about for each untagged one.
func (e leftoverEnv) routeLeftovers(
	logger zerolog.Logger,
	fam netutil.Family,
	fib int,
	isShape func(route.TableRoute) bool,
	warnUntagged bool,
) []server.Leftover {
	routes, err := e.dumpRoutes(fam, fib)
	if err != nil {
		logger.Warn().Err(err).
			Int("fib", fib).
			Msg("cannot read routes to look for leftovers")
		return nil
	}
	// Default routes go first, the reverse of the order they are added in:
	// the gateway of a FIB default route is reached through the subnet
	// route.
	slices.SortStableFunc(routes, func(a, b route.TableRoute) int {
		return min(a.Dst.Bits(), 1) - min(b.Dst.Bits(), 1)
	})
	var leftovers []server.Leftover
	for _, r := range routes {
		if !isShape(r) {
			continue
		}
		l := server.Leftover{
			Description:   fmt.Sprintf("route %s in fib %d", r, fib),
			Remove:        e.removeRoute(fam, fib, r),
			ManualCommand: manualRouteDelete(fib, r),
		}
		if !isTaggedRoute(r) {
			if !warnUntagged {
				continue
			}
			l.Description += ", untagged: it may not be spoofdpi's"
			l.Remove = nil
		}
		leftovers = append(leftovers, l)
	}
	return leftovers
}

// removeRoute returns the Remove of the leftover route want of fam in fib.
// It reads the routes again and deletes want only if it is still there as
// it was. The delete carries the gateway of want, so another route to the
// same destination stays.
func (e leftoverEnv) removeRoute(
	fam netutil.Family,
	fib int,
	want route.TableRoute,
) func() error {
	return func() error {
		routes, err := e.dumpRoutes(fam, fib)
		if err != nil {
			return err
		}
		if !slices.Contains(routes, want) {
			return errors.New("the route changed or went away since it was found")
		}
		err = e.deleteRoute(fib, route.TableRoute{
			Dst:         want.Dst,
			Gateway:     want.Gateway,
			GatewayLink: want.GatewayLink,
		})
		return withRootHint(err)
	}
}

// removeTun destroys the leftover tun, unless a process has opened it since
// it was found: Destroy would then block until that process closes it.
func (e leftoverEnv) removeTun() error {
	opened, err := e.tunOpened(e.tunName)
	if err != nil {
		return err
	}
	if opened {
		return errors.New("a process opened it since it was found")
	}
	return withRootHint(e.destroy(e.tunName))
}

// afterReset returns the routes of run that are still there: the tagged
// routes through its tun in the main FIB and the tagged routes of its FIB.
func (e leftoverEnv) afterReset(logger zerolog.Logger, run runInfo) []server.Leftover {
	return slices.Concat(
		e.mainFIBLeftovers(logger, run.TUNIndex, false),
		e.fibLeftovers(logger, run.FIB, false),
	)
}

// isTaggedRoute reports whether r carries routeTag.
func isTaggedRoute(r route.TableRoute) bool {
	return r.Flags&routeTag != 0
}

// kernelRouteFlags mark the routes that the kernel makes or keeps for
// itself, such as those of an interface address, and those that drop
// traffic. FreeBSD has no RTF_WASCLONED: it no longer clones routes.
const kernelRouteFlags = unix.RTF_DYNAMIC | unix.RTF_LLDATA | unix.RTF_PINNED |
	unix.RTF_LOCAL | unix.RTF_BROADCAST | unix.RTF_MULTICAST |
	unix.RTF_REJECT | unix.RTF_BLACKHOLE

// isStaticRoute reports whether r was added by a program, as `route add`
// does, rather than by the kernel, and forwards traffic.
func isStaticRoute(r route.TableRoute) bool {
	return r.Flags&unix.RTF_STATIC != 0 && r.Flags&kernelRouteFlags == 0
}

// isFIBRouteShape reports whether r has the shape of a route that spoofdpi
// adds to its FIB, the tag aside: an IPv4 default route through a gateway
// or an interface, or an IPv4 route to a subnet through an interface. A
// route to a loopback address, such as the one the rc scripts add to every
// FIB, is not one.
func isFIBRouteShape(r route.TableRoute) bool {
	if !isStaticRoute(r) || !r.Dst.Addr().Is4() || r.Dst.Addr().IsLoopback() {
		return false
	}
	viaGateway := r.Flags&unix.RTF_GATEWAY != 0 && r.Gateway.IsValid()
	viaLink := r.Flags&unix.RTF_GATEWAY == 0 && r.GatewayLink > 0
	if r.Dst.Bits() == 0 {
		return viaGateway || viaLink
	}
	return viaLink
}

// isMainFIBRouteShape reports whether r has the shape of a route that
// spoofdpi adds to the main FIB, the tag aside: a route of
// mainFIBTargetsV4 or mainFIBTargetV6 through the interface tunIndex.
func isMainFIBRouteShape(r route.TableRoute, tunIndex int) bool {
	isTarget := r.Dst == mainFIBTargetV6 || slices.Contains(mainFIBTargetsV4, r.Dst)
	return isTarget && isStaticRoute(r) &&
		r.Flags&unix.RTF_GATEWAY == 0 && r.GatewayLink == tunIndex
}

// manualRouteDelete returns the route(8) command that deletes r from fib.
func manualRouteDelete(fib int, r route.TableRoute) string {
	args := []string{"route", "-n", "delete"}
	if r.Dst.Addr().Is6() {
		args = append(args, "-inet6")
	}
	if r.Dst.Bits() == 0 {
		args = append(args, "default")
	} else {
		args = append(args, "-net", r.Dst.String())
	}
	switch {
	case r.Gateway.IsValid():
		args = append(args, r.Gateway.String())
	case r.IfName != "":
		args = append(args, "-interface", r.IfName)
	}
	args = append(args, "-fib", strconv.Itoa(fib))
	return strings.Join(args, " ")
}

// tunInterfaceIndex returns the index of the interface name, 0 when it
// does not exist, and whether it is a tun: an interface of type IFT_PPP, as
// the tun driver creates them.
func tunInterfaceIndex(name string) (int, bool, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return 0, false, err
	}
	i := slices.IndexFunc(
		ifaces,
		func(iface net.Interface) bool { return iface.Name == name },
	)
	if i < 0 {
		return 0, false, nil
	}
	index := ifaces[i].Index
	rib, err := xroute.FetchRIB(unix.AF_UNSPEC, xroute.RIBTypeInterface, index)
	if err != nil {
		return 0, false, fmt.Errorf("read interface %s: %w", name, err)
	}
	msgs, err := xroute.ParseRIB(xroute.RIBTypeInterface, rib)
	if err != nil {
		return 0, false, fmt.Errorf("parse interface %s: %w", name, err)
	}
	for _, msg := range msgs {
		m, ok := msg.(*xroute.InterfaceMessage)
		if !ok || m.Index != index {
			continue
		}
		for _, sys := range m.Sys() {
			if mx, ok := sys.(*xroute.InterfaceMetrics); ok {
				return index, mx.Type == syscall.IFT_PPP, nil
			}
		}
	}
	return 0, false, fmt.Errorf("interface %s: no type in the interface list", name)
}
