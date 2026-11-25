package route

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/xvzc/spoofdpi/internal/netutil"
)

// linkInfoOf and defaultLinksOf read the OS's link kinds and default
// routes. Tests replace them.
var (
	linkInfoOf     = linkInfo
	defaultLinksOf = defaultLinks
)

// ClassifyPath classifies the egress of the kernel's route p, whose Route
// is the Egress's Route. A link that cannot be read is LinkUnknown, and
// default routes that cannot be read are left out of the classification
// and noted in the reason. A route through a loopback link is an error
// that wraps ErrNoIPv4 or ErrNoIPv6: it never leaves the host.
func ClassifyPath(p *Path) (*Egress, error) {
	link, err := linkInfoOf(p.Iface.Index)
	if err != nil {
		link = LinkInfo{
			Index:  p.Iface.Index,
			Name:   p.Iface.Name,
			Kind:   LinkUnknown,
			Detail: "link unreadable: " + err.Error(),
		}
	}

	if link.Kind == LinkLoopback {
		return nil, fmt.Errorf(
			"route to %s goes through loopback %s: %w",
			p.Dst, describeLink(link), noRouteError(p.Family),
		)
	}

	// Default routes only tell an uplink from a VPN when the link alone
	// cannot.
	var others []LinkInfo
	var othersErr error
	if link.Kind != LinkPhysical && link.Kind != LinkVPN {
		others, othersErr = defaultLinksOf(p.Family)
	}

	class, reason := ClassifyEgress(link, others)
	if othersErr != nil {
		reason += " (default routes unreadable: " + othersErr.Error() + ")"
	}
	return &Egress{Route: *p.Route(), Link: link, Class: class, Reason: reason}, nil
}

// ErrBadGateway matches, by errors.Is, the errors of DiscoverEgress that
// come from the gateway it was given, as opposed to the system's route
// lookup.
var ErrBadGateway = errors.New("unusable gateway")

// DiscoverEgress discovers and classifies the egress of fam.
//
// Without a gateway, the egress is the kernel's route to the internet.
// With one, as ResolveGateway or ResolveGateway6 take it, the Route is the
// one through that gateway, while the link, class and reason are those of
// the kernel's route to the internet: a full-tunnel VPN carries the
// traffic whatever gateway is given. When the kernel has no route of fam,
// the link is the gateway's interface. An error of the gateway matches
// ErrBadGateway.
func DiscoverEgress(fam netutil.Family, gateway net.IP, zone string) (*Egress, error) {
	if gateway == nil {
		path, err := Lookup(probeDst(fam))
		if err != nil {
			return nil, fmt.Errorf("discover egress: %w", err)
		}
		return ClassifyPath(path)
	}

	var route *Route
	var err error
	if fam == netutil.FamilyV6 {
		route, err = ResolveGateway6(gateway, zone)
	} else {
		route, err = ResolveGateway(gateway)
	}
	if err != nil {
		return nil, &badGatewayError{err: err}
	}

	path, err := Lookup(probeDst(fam))
	switch {
	case errors.Is(err, noRouteError(fam)):
		path = pathOfRoute(route)
	case err != nil:
		return nil, fmt.Errorf("discover egress: %w", err)
	}

	egress, err := ClassifyPath(path)
	if err != nil {
		return nil, err
	}
	egress.Route = *route
	return egress, nil
}

// badGatewayError is an error of the gateway given to DiscoverEgress. It
// keeps the text of err and matches ErrBadGateway.
type badGatewayError struct{ err error }

func (e *badGatewayError) Error() string { return e.err.Error() }

func (e *badGatewayError) Unwrap() error { return e.err }

func (e *badGatewayError) Is(target error) bool { return target == ErrBadGateway }

// noRouteError returns the sentinel for a missing route of fam.
func noRouteError(fam netutil.Family) error {
	if fam == netutil.FamilyV6 {
		return ErrNoIPv6
	}
	return ErrNoIPv4
}

// pathOfRoute returns the path to the internet through route, for a
// classification that has no kernel route to go by.
func pathOfRoute(route *Route) *Path {
	p := &Path{
		Family: route.Family,
		Dst:    probeDst(route.Family),
		Iface:  route.Iface,
		Zone:   route.Zone,
	}
	if gw, ok := netip.AddrFromSlice(route.Gateway); ok {
		p.Gateway = gw.Unmap().WithZone("")
	}
	if src, ok := netip.AddrFromSlice(route.LocalIP); ok {
		p.Src = src.Unmap()
	}
	return p
}
