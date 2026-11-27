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
			Apply:       command("ifconfig utun9 10.200.0.1 10.200.0.2 up"),
			Reset:       command("ifconfig utun9 down"),
		},
		{
			Description: "add scoped default route via physical interface",
			Apply:       command("route add -ifscope en0 default 192.168.1.1"),
			Reset:       command("route delete -ifscope en0 default 192.168.1.1"),
		},
		{
			Description: "add CIDR route 10.200.0.0/30 via TUN",
			Apply:       command("route -n add -net 10.200.0.0/30 -interface utun9"),
			Reset:       command("route -n delete -net 10.200.0.0/30 -interface utun9"),
		},
		{
			Description: "add CIDR route 0.0.0.0/1 via TUN",
			Apply:       command("route -n add -net 0.0.0.0/1 -interface utun9"),
			Reset:       command("route -n delete -net 0.0.0.0/1 -interface utun9"),
		},
		{
			Description: "add CIDR route 128.0.0.0/1 via TUN",
			Apply:       command("route -n add -net 128.0.0.0/1 -interface utun9"),
			Reset:       command("route -n delete -net 128.0.0.0/1 -interface utun9"),
		},
	}
	ipv6Job := server.NetworkJob{
		Description: "add IPv6 route 2000::/3 via TUN",
		Apply:       command("route -n add -inet6 -net 2000::/3 -interface utun9"),
		Reset:       command("route -n delete -inet6 -net 2000::/3 -interface utun9"),
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
				IPv6Enabled:   tc.ipv6Enabled,
				HasIPv6Egress: tc.hasIPv6Egress,
			}

			assert.Equal(t, tc.want, buildJobs(info))
		})
	}
}

func TestBuildJobs_Darwin_NoGateway(t *testing.T) {
	info := &tunNetworkInfoDarwin{
		GatewayIP:        "",
		PhysIfaceName:    "ppp0",
		TUNName:          "utun9",
		TunLocalIP:       "10.200.0.1",
		TunRemoteIP:      "10.200.0.2",
		RouteTargetCIDRs: []string{"10.200.0.0/30", "0.0.0.0/1", "128.0.0.0/1"},
		IPv6Enabled:      false,
		HasIPv6Egress:    false,
	}

	jobs := buildJobs(info)

	assert.Equal(t, server.NetworkJob{
		Description: "add scoped default route via physical interface",
		Apply:       command("route add -ifscope ppp0 default -interface ppp0"),
		Reset:       command("route delete -ifscope ppp0 default -interface ppp0"),
	}, jobs[1])
	assert.Len(t, jobs, 5)
}
