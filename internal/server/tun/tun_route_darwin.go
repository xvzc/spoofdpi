//go:build darwin

package tun

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/netif"
	"github.com/xvzc/spoofdpi/internal/route"
	"golang.org/x/sys/unix"
)

// routeTag marks the routes that TUN mode adds, so that a later run can
// tell them from the routes of the system and of other programs. darwin
// drops RTF_PROTO3 from RTM_ADD, so the tag is RTF_PROTO2. The tag alone
// proves nothing: the kernel and other programs may set the same bit, so
// the leftover search also checks a route's exact shape.
const routeTag = unix.RTF_PROTO2

// defaultDst4 is the destination of the IPv4 default route.
var defaultDst4 = netip.PrefixFrom(netip.IPv4Unspecified(), 0)

// addRouteAction adds route to the routing table.
type addRouteAction struct {
	route route.TableRoute
}

func (a addRouteAction) Run() error {
	return route.AddRoute(0, a.route)
}

func (a addRouteAction) String() string {
	return "add route " + a.route.String()
}

// deleteRouteAction deletes route from the routing table. darwin finds the
// route by destination, netmask and scope.
type deleteRouteAction struct {
	route route.TableRoute
}

func (a deleteRouteAction) Run() error {
	return route.DeleteRoute(0, a.route)
}

func (a deleteRouteAction) String() string {
	return "delete route " + a.route.String()
}

// resetScopedDefaultAction deletes route, the scoped default route that
// this run added, only while the routing table shows it still as this
// run's. Otherwise it logs a warning to logger and keeps the route.
type resetScopedDefaultAction struct {
	logger zerolog.Logger
	route  route.TableRoute
}

func (a resetScopedDefaultAction) Run() error {
	return resetScopedDefault(a.logger, systemRouteTable, a.route)
}

func (a resetScopedDefaultAction) String() string {
	return "delete route " + a.route.String() + " if TUN mode's"
}

// tunAddrAction gives the TUN interface name its point-to-point address,
// local with the netmask of its prefix and remote at the other end, and
// brings the interface up, as `ifconfig name local remote up` does.
type tunAddrAction struct {
	name   string
	local  netip.Prefix
	remote netip.Addr
}

func (a tunAddrAction) Run() error {
	if err := netif.AddAddr4(a.name, a.local, a.remote); err != nil {
		return err
	}
	return netif.SetUp(a.name)
}

func (a tunAddrAction) String() string {
	return fmt.Sprintf("set address %s remote %s on %s and bring it up",
		a.local, a.remote, a.name)
}

// linkDownAction brings the interface name down, as `ifconfig name down`
// does.
type linkDownAction struct {
	name string
}

func (a linkDownAction) Run() error {
	return netif.SetDown(a.name)
}

func (a linkDownAction) String() string {
	return "bring " + a.name + " down"
}

// isScopedDefault4 reports whether r is an IPv4 default route scoped to an
// interface (RTF_IFSCOPE), the interface of r.Index.
func isScopedDefault4(r route.TableRoute) bool {
	return r.Dst == defaultDst4 && r.Flags&unix.RTF_IFSCOPE != 0
}

// isOwnScopedDefaultShape reports whether r has exactly the shape of the
// scoped default route that TUN mode adds: a static, tagged IPv4 default
// scoped to r.Index, not cloned by the kernel, through either an IPv4
// gateway or the scoped interface itself.
func isOwnScopedDefaultShape(r route.TableRoute) bool {
	if !isScopedDefault4(r) || r.Flags&routeTag == 0 ||
		r.Flags&unix.RTF_STATIC == 0 || r.Flags&unix.RTF_WASCLONED != 0 {
		return false
	}
	if r.Flags&unix.RTF_GATEWAY != 0 {
		return r.Gateway.Is4() && r.GatewayLink == 0
	}
	return !r.Gateway.IsValid() && r.Index > 0 && r.GatewayLink == r.Index
}

// isLiveTUNRoute reports whether r is a route that a running TUN mode
// instance holds: a static, tagged route, not cloned by the kernel, through
// a utun. The utun and its routes go away with the process that opened it,
// so such a route outlives no crash. names maps interface indexes to names.
func isLiveTUNRoute(r route.TableRoute, names map[int]string) bool {
	if r.Flags&routeTag == 0 || r.Flags&unix.RTF_STATIC == 0 ||
		r.Flags&unix.RTF_WASCLONED != 0 {
		return false
	}
	return isUTUN(names[r.GatewayLink]) || isUTUN(names[r.Index]) ||
		isUTUN(r.IfName)
}

// isUTUN reports whether name is the name of a utun interface.
func isUTUN(name string) bool {
	return strings.HasPrefix(name, "utun")
}

// deleteRouteCommand returns the route command that deletes r by hand. r
// is either a scoped default route of the interface ifName or a route
// through the interface ifName.
func deleteRouteCommand(r route.TableRoute, ifName string) string {
	if isScopedDefault4(r) {
		target := "-interface " + ifName
		if r.Gateway.IsValid() {
			target = r.Gateway.String()
		}
		return fmt.Sprintf("route -n delete -ifscope %s default %s", ifName, target)
	}
	family := ""
	if r.Dst.Addr().Is6() {
		family = "-inet6 "
	}
	return fmt.Sprintf("route -n delete %s-net %s -interface %s", family, r.Dst, ifName)
}
