//go:build darwin

package tun

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xvzc/spoofdpi/internal/server"
)

func TestBuildJobs_Darwin(t *testing.T) {
	ipv4Jobs := []server.NetworkJob{
		{
			Description: "configure TUN interface address",
			Apply:       "ifconfig utun9 10.200.0.1 10.200.0.2 up",
			Reset:       "ifconfig utun9 down",
		},
		{
			Description: "add scoped default route via physical interface",
			Apply:       "route add -ifscope en0 default 192.168.1.1",
			Reset:       "route delete -ifscope en0 default 192.168.1.1",
		},
		{
			Description: "add CIDR route 10.200.0.0/30 via TUN",
			Apply:       "route -n add -net 10.200.0.0/30 -interface utun9",
			Reset:       "route -n delete -net 10.200.0.0/30 -interface utun9",
		},
		{
			Description: "add CIDR route 0.0.0.0/1 via TUN",
			Apply:       "route -n add -net 0.0.0.0/1 -interface utun9",
			Reset:       "route -n delete -net 0.0.0.0/1 -interface utun9",
		},
		{
			Description: "add CIDR route 128.0.0.0/1 via TUN",
			Apply:       "route -n add -net 128.0.0.0/1 -interface utun9",
			Reset:       "route -n delete -net 128.0.0.0/1 -interface utun9",
		},
	}
	ipv6Job := server.NetworkJob{
		Description: "add IPv6 route 2000::/3 via TUN",
		Apply:       "route -n add -inet6 -net 2000::/3 -interface utun9",
		Reset:       "route -n delete -inet6 -net 2000::/3 -interface utun9",
		Optional:    true,
		Warning:     ipv6RejectWarning,
	}

	tcs := []struct {
		name          string
		hasIPv6Egress bool
		want          []server.NetworkJob
	}{
		{"without IPv6 egress", false, ipv4Jobs},
		{"with IPv6 egress the IPv6 route goes last", true, append(ipv4Jobs, ipv6Job)},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			info := &tunNetworkInfoDarwin{
				GatewayIP:     "192.168.1.1",
				PhysIfaceName: "en0",
				TUNName:       "utun9",
				TunLocalIP:    "10.200.0.1",
				TunRemoteIP:   "10.200.0.2",
				RouteTargetCIDRs: []string{
					"10.200.0.0/30",
					"0.0.0.0/1",
					"128.0.0.0/1",
				},
				HasIPv6Egress: tc.hasIPv6Egress,
			}

			assert.Equal(t, tc.want, buildJobs(info))
		})
	}
}
