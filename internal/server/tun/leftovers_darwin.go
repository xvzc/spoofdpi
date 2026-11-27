//go:build darwin

package tun

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/route"
	"github.com/xvzc/spoofdpi/internal/server"
)

// routeTable reads and changes the routing table for the leftover search.
// Tests replace it with a fake.
type routeTable struct {
	// dump returns the routes of a family, as route.DumpRoutes does.
	dump func(fam netutil.Family) ([]route.TableRoute, error)
	// delete deletes a route, as route.DeleteRoute does.
	delete func(r route.TableRoute) error
	// interfaceNames maps the indexes of the interfaces to their names.
	interfaceNames func() (map[int]string, error)
}

// systemRouteTable is the routing table of the host.
var systemRouteTable = routeTable{
	dump: func(fam netutil.Family) ([]route.TableRoute, error) {
		return route.DumpRoutes(fam, 0)
	},
	delete: func(r route.TableRoute) error {
		return route.DeleteRoute(0, r)
	},
	interfaceNames: func() (map[int]string, error) {
		ifaces, err := net.Interfaces()
		if err != nil {
			return nil, err
		}
		names := make(map[int]string, len(ifaces))
		for _, iface := range ifaces {
			names[iface.Index] = iface.Name
		}
		return names, nil
	},
}

// runRoutes holds the routes that the jobs of this run add, for
// CheckLeftoversAfterReset.
type runRoutes struct {
	mu     sync.Mutex
	routes []route.TableRoute
}

func (s *runRoutes) setRoutes(routes []route.TableRoute) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.routes = routes
}

func (s *runRoutes) get() []route.TableRoute {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.routes
}

// thisRun holds the routes of this run's jobs, set by BuildJobs.
var thisRun runRoutes

// CleanLeftovers removes the scoped default route that an earlier TUN mode
// run left behind when it ended without restoring it, such as on a crash.
// The routes through the utun need no cleanup: they go away with the utun
// when the process ends. It runs at startup in every mode, before anything
// reads the routes, and never fails the start.
//
// It leaves the routes alone while another instance runs in TUN mode, which
// shows in a tagged route through a utun. It removes a scoped default route
// only when it has exactly the shape and tag that TUN mode adds and is the
// only scoped default route of its interface; it warns about the other
// tagged ones, with the command that removes them by hand.
func CleanLeftovers(logger zerolog.Logger, opts CleanupOptions) {
	cleanLeftovers(logger, systemRouteTable)
}

func cleanLeftovers(logger zerolog.Logger, table routeTable) {
	routes, names, err := readRoutes(table)
	if err != nil {
		logger.Warn().Err(err).Msg("failed to look for TUN mode leftovers")
		return
	}
	if live, ok := liveTUNRoute(routes, names); ok {
		logger.Info().
			Stringer("route", live).
			Msg("another spoofdpi instance is running in TUN mode; " +
				"leaving its routes alone")
		return
	}
	server.RemoveLeftovers(logger, scopedDefaultLeftovers(table, routes, names))
}

// readRoutes returns the IPv4 routes of table and the names of the
// interfaces. Without the names, a route through a running instance's
// utun cannot be told apart, so the search stops.
func readRoutes(table routeTable) ([]route.TableRoute, map[int]string, error) {
	routes, err := table.dump(netutil.FamilyV4)
	if err != nil {
		return nil, nil, err
	}
	names, err := table.interfaceNames()
	if err != nil {
		return nil, nil, fmt.Errorf("read interface names: %w", err)
	}
	return routes, names, nil
}

// liveTUNRoute returns a route among routes that a running TUN mode
// instance holds, if there is one.
func liveTUNRoute(
	routes []route.TableRoute,
	names map[int]string,
) (route.TableRoute, bool) {
	for _, r := range routes {
		if isLiveTUNRoute(r, names) {
			return r, true
		}
	}
	return route.TableRoute{}, false
}

// scopedDefaultLeftovers returns the tagged scoped default routes among
// routes, read from table. The ones that are removable can be removed
// through table; the others carry no Remove.
func scopedDefaultLeftovers(
	table routeTable,
	routes []route.TableRoute,
	names map[int]string,
) []server.Leftover {
	var leftovers []server.Leftover
	for _, r := range routes {
		if !isScopedDefault4(r) || r.Flags&routeTag == 0 {
			continue
		}
		ifName := interfaceName(r, names)
		l := server.Leftover{
			Description:   "scoped default route " + r.String(),
			ManualCommand: deleteRouteCommand(r, ifName),
		}
		if isRemovableScopedDefault(r, routes) {
			l.Remove = func() error { return removeScopedDefault(table, r) }
		}
		leftovers = append(leftovers, l)
	}
	return leftovers
}

// isRemovableScopedDefault reports whether r, a route among routes, is a
// scoped default route that TUN mode added and that can be deleted safely.
// darwin deletes a scoped route by its destination and scope alone, so r
// must be the only scoped default route of its interface.
func isRemovableScopedDefault(r route.TableRoute, routes []route.TableRoute) bool {
	if !isOwnScopedDefaultShape(r) {
		return false
	}
	n := 0
	for _, other := range routes {
		if isScopedDefault4(other) && other.Index == r.Index {
			n++
		}
	}
	return n == 1
}

// removeScopedDefault deletes want, a removable scoped default route,
// after it reads the routes again and finds want unchanged and still
// removable, and no running instance.
func removeScopedDefault(table routeTable, want route.TableRoute) error {
	routes, names, err := readRoutes(table)
	if err != nil {
		return err
	}
	if live, ok := liveTUNRoute(routes, names); ok {
		return fmt.Errorf("another spoofdpi instance is running in TUN mode: %s", live)
	}
	if !hasRemovableScopedDefault(routes, func(r route.TableRoute) bool {
		return sameRoute(r, want)
	}) {
		return errors.New("the route changed before it could be removed")
	}
	return deleteScopedDefault(table, want)
}

// resetScopedDefault deletes added, the scoped default route that this
// run added, when the routes show it still removable: tagged, of its exact
// shape and the only one of its interface. Otherwise the scoped default
// route of the interface is no longer this run's, and it logs a warning
// and keeps it.
func resetScopedDefault(
	logger zerolog.Logger,
	table routeTable,
	added route.TableRoute,
) error {
	routes, err := table.dump(netutil.FamilyV4)
	if err != nil {
		return err
	}
	if !hasRemovableScopedDefault(routes, func(r route.TableRoute) bool {
		return isScopedDefault4(r) && r.Index == added.Index &&
			r.Gateway == added.Gateway && r.GatewayLink == added.GatewayLink
	}) {
		logger.Warn().
			Stringer("route", added).
			Msg("the scoped default route is no longer the one TUN mode added; " +
				"keeping it")
		return nil
	}
	return deleteScopedDefault(table, added)
}

// hasRemovableScopedDefault reports whether the first route among routes
// that match selects is a removable scoped default route.
func hasRemovableScopedDefault(
	routes []route.TableRoute,
	match func(route.TableRoute) bool,
) bool {
	for _, r := range routes {
		if match(r) {
			return isRemovableScopedDefault(r, routes)
		}
	}
	return false
}

// deleteScopedDefault deletes the scoped default route r from table.
func deleteScopedDefault(table routeTable, r route.TableRoute) error {
	if err := table.delete(r); err != nil {
		return withRootHint(err)
	}
	return nil
}

// sameRoute reports whether a and b are the same route of a dump. The
// interface name does not count: a dump fills it in from the index.
func sameRoute(a, b route.TableRoute) bool {
	return a.Dst == b.Dst && a.Gateway == b.Gateway &&
		a.GatewayLink == b.GatewayLink && a.Index == b.Index && a.Flags == b.Flags
}

// interfaceName returns the name of the interface of r, a route of a dump.
func interfaceName(r route.TableRoute, names map[int]string) string {
	if name := names[r.Index]; name != "" {
		return name
	}
	if r.IfName != "" {
		return r.IfName
	}
	return fmt.Sprintf("<interface %d>", r.Index)
}

// CheckLeftoversAfterReset warns about the routes of this run that are
// still there after ResetJobs restored the network configuration, which
// points to a bug in a job's Reset. It removes nothing.
func CheckLeftoversAfterReset(logger zerolog.Logger) {
	checkLeftoversAfterReset(logger, systemRouteTable, thisRun.get())
}

func checkLeftoversAfterReset(
	logger zerolog.Logger,
	table routeTable,
	added []route.TableRoute,
) {
	dumps := make(map[netutil.Family][]route.TableRoute)
	var leftovers []server.Leftover
	for _, a := range added {
		fam := netutil.FamilyV4
		if a.Dst.Addr().Is6() {
			fam = netutil.FamilyV6
		}
		routes, ok := dumps[fam]
		if !ok {
			var err error
			if routes, err = table.dump(fam); err != nil {
				logger.Warn().Err(err).
					Msg("failed to look for the routes left after restoring them")
				return
			}
			dumps[fam] = routes
		}
		for _, r := range routes {
			if isAddedRoute(r, a) {
				leftovers = append(leftovers, server.Leftover{
					Description:   "route " + r.String(),
					ManualCommand: deleteRouteCommand(r, a.IfName),
				})
			}
		}
	}
	server.WarnLeftoversAfterReset(logger, leftovers)
}

// isAddedRoute reports whether r, a route of a dump, is a, a route that
// this run added: a scoped default route of the same interface, or a route
// to the same destination through the same TUN, either one tagged.
func isAddedRoute(r, a route.TableRoute) bool {
	if r.Dst != a.Dst || r.Flags&routeTag == 0 {
		return false
	}
	if isScopedDefault4(a) {
		return isScopedDefault4(r) && r.Index == a.Index
	}
	return r.GatewayLink == a.GatewayLink
}
