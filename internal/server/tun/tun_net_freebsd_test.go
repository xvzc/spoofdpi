//go:build freebsd

package tun

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xvzc/spoofdpi/internal/server"
)

func TestBuildJobs_FreeBSD(t *testing.T) {
	ipv4Jobs := []server.NetworkJob{
		{
			Description: "configure TUN interface address",
			Apply:       "ifconfig tun-spoofdpi 10.200.0.1 10.200.0.2 up",
			Reset:       "ifconfig tun-spoofdpi destroy",
		},
		{
			Description: "add FIB subnet route",
			Apply:       "route add -net 192.168.1.0/24 -iface em0 -fib 3",
			Reset:       "route delete -net 192.168.1.0/24 -iface em0 -fib 3",
		},
		{
			Description: "add FIB default route",
			Apply:       "route add default 192.168.1.1 -fib 3",
			Reset:       "route delete default -fib 3",
		},
		{
			Description: "add CIDR route 10.200.0.0/30 via TUN",
			Apply:       "route -n add -net 10.200.0.0/30 -interface tun-spoofdpi",
			Reset:       "route -n delete -net 10.200.0.0/30 -interface tun-spoofdpi",
		},
		{
			Description: "add CIDR route 0.0.0.0/1 via TUN",
			Apply:       "route -n add -net 0.0.0.0/1 -interface tun-spoofdpi",
			Reset:       "route -n delete -net 0.0.0.0/1 -interface tun-spoofdpi",
		},
		{
			Description: "add CIDR route 128.0.0.0/1 via TUN",
			Apply:       "route -n add -net 128.0.0.0/1 -interface tun-spoofdpi",
			Reset:       "route -n delete -net 128.0.0.0/1 -interface tun-spoofdpi",
		},
	}
	ipv6Job := server.NetworkJob{
		Description: "add IPv6 route 2000::/3 via TUN",
		Apply:       "route -n add -inet6 -net 2000::/3 -interface tun-spoofdpi",
		Reset:       "route -n delete -inet6 -net 2000::/3 -interface tun-spoofdpi",
		Optional:    true,
		Warning:     ipv6RejectWarning,
	}

	tcs := []struct {
		name          string
		ipv6Enabled   bool
		hasIPv6Egress bool
		want          []server.NetworkJob
	}{
		{"ipv6 off without IPv6 egress", false, false, ipv4Jobs},
		{"ipv6 off with IPv6 egress adds no IPv6 route", false, true, ipv4Jobs},
		{"ipv6 on without IPv6 egress", true, false, ipv4Jobs},
		{
			"ipv6 on with IPv6 egress the IPv6 route goes last",
			true,
			true,
			append(ipv4Jobs, ipv6Job),
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			info := &tunNetworkInfoFreeBSD{
				FIBID:         3,
				GatewayIP:     "192.168.1.1",
				PhysIfaceName: "em0",
				PhysIfaceCIDR: "192.168.1.0/24",
				TUNName:       "tun-spoofdpi",
				TunLocalIP:    "10.200.0.1",
				TunRemoteIP:   "10.200.0.2",
				RouteTargetCIDRs: []string{
					"10.200.0.0/30",
					"0.0.0.0/1",
					"128.0.0.0/1",
				},
				IPv6Enabled:   tc.ipv6Enabled,
				HasIPv6Egress: tc.hasIPv6Egress,
			}

			assert.Equal(t, tc.want, buildJobs(info))
		})
	}
}
