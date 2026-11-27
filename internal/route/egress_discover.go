package route

import (
	"fmt"

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

// DiscoverEgress discovers and classifies the egress of fam: the kernel's
// route to the internet.
func DiscoverEgress(fam netutil.Family) (*Egress, error) {
	path, err := Lookup(probeDst(fam))
	if err != nil {
		return nil, fmt.Errorf("discover egress: %w", err)
	}
	return ClassifyPath(path)
}

// noRouteError returns the sentinel for a missing route of fam.
func noRouteError(fam netutil.Family) error {
	if fam == netutil.FamilyV6 {
		return ErrNoIPv6
	}
	return ErrNoIPv4
}
