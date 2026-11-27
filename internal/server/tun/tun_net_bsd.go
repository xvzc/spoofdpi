//go:build darwin || freebsd

package tun

import "github.com/xvzc/spoofdpi/internal/route"

// gatewayIP returns the next hop of rt as the TUN job builders print it,
// or "" when rt has no gateway, as on a point-to-point uplink such as
// PPP.
func gatewayIP(rt *route.Route) string {
	if rt.Gateway == nil {
		return ""
	}
	return rt.Gateway.String()
}
