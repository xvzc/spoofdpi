package route

import (
	"fmt"

	"github.com/xvzc/spoofdpi/internal/netutil"
)

// linkInfoOf reads the OS's link kinds. Tests replace it.
var linkInfoOf = linkInfo

// Egress is the egress of one family.
type Egress struct {
	// Route has the egress interface, the gateway (nil for an interface
	// route), the zone, and the source address as LocalIP.
	Route Route
}

// egressOf returns the egress of the kernel's route p. A route through a
// loopback link is an error that wraps ErrNoIPv4 or ErrNoIPv6: it never
// leaves the host. A link that cannot be read counts as not loopback.
func egressOf(p *Path) (*Egress, error) {
	link, err := linkInfoOf(p.Iface.Index)
	if err == nil && link.Kind == LinkLoopback {
		return nil, fmt.Errorf(
			"route to %s goes through loopback %s: %w",
			p.Dst, describeLink(link), noRouteError(p.Family),
		)
	}
	return &Egress{Route: *p.Route()}, nil
}

// DiscoverEgress discovers the egress of fam: the kernel's route to the
// internet.
func DiscoverEgress(fam netutil.Family) (*Egress, error) {
	path, err := Lookup(probeDst(fam))
	if err != nil {
		return nil, fmt.Errorf("discover egress: %w", err)
	}
	return egressOf(path)
}

// noRouteError returns the sentinel for a missing route of fam.
func noRouteError(fam netutil.Family) error {
	if fam == netutil.FamilyV6 {
		return ErrNoIPv6
	}
	return ErrNoIPv4
}
