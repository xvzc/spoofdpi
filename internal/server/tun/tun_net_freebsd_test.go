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
			Apply:       command("ifconfig tun-spoofdpi inet 10.200.0.1/30 up"),
			Reset:       command("ifconfig tun-spoofdpi destroy"),
		},
		{
			Description: "add FIB subnet route",
			Apply:       command("route add -net 192.168.1.0/24 -iface em0 -fib 3"),
			Reset:       command("route delete -net 192.168.1.0/24 -iface em0 -fib 3"),
		},
		{
			Description: "add FIB default route",
			Apply:       command("route add default 192.168.1.1 -fib 3"),
			Reset:       command("route delete default -fib 3"),
		},
		{
			Description: "add CIDR route 0.0.0.0/1 via TUN",
			Apply:       command("route -n add -net 0.0.0.0/1 -interface tun-spoofdpi"),
			Reset:       command("route -n delete -net 0.0.0.0/1 -interface tun-spoofdpi"),
		},
		{
			Description: "add CIDR route 128.0.0.0/1 via TUN",
			Apply:       command("route -n add -net 128.0.0.0/1 -interface tun-spoofdpi"),
			Reset:       command("route -n delete -net 128.0.0.0/1 -interface tun-spoofdpi"),
		},
	}
	ipv6Job := server.NetworkJob{
		Description: "add IPv6 route 2000::/3 via TUN",
		Apply:       command("route -n add -inet6 -net 2000::/3 -interface tun-spoofdpi"),
		Reset: command(
			"route -n delete -inet6 -net 2000::/3 -interface tun-spoofdpi",
		),
		Optional: true,
		Warning:  ipv6RejectWarning,
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
				TunPrefixLen:  30,
				RouteTargetCIDRs: []string{
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

func TestBuildJobs_FreeBSD_NoGateway(t *testing.T) {
	routeTargets := []string{"0.0.0.0/1", "128.0.0.0/1"}
	tunAddressJob := server.NetworkJob{
		Description: "configure TUN interface address",
		Apply:       command("ifconfig tun-spoofdpi inet 10.200.0.1/30 up"),
		Reset:       command("ifconfig tun-spoofdpi destroy"),
	}
	tunRouteJobs := []server.NetworkJob{
		{
			Description: "add CIDR route 0.0.0.0/1 via TUN",
			Apply:       command("route -n add -net 0.0.0.0/1 -interface tun-spoofdpi"),
			Reset:       command("route -n delete -net 0.0.0.0/1 -interface tun-spoofdpi"),
		},
		{
			Description: "add CIDR route 128.0.0.0/1 via TUN",
			Apply:       command("route -n add -net 128.0.0.0/1 -interface tun-spoofdpi"),
			Reset:       command("route -n delete -net 128.0.0.0/1 -interface tun-spoofdpi"),
		},
	}
	fibDefaultJob := server.NetworkJob{
		Description: "add FIB default route",
		Apply:       command("route add default -interface ppp0 -fib 3"),
		Reset:       command("route delete default -fib 3"),
	}

	tcs := []struct {
		name          string
		physIfaceCIDR string
		physIfaceP2P  bool
		want          []server.NetworkJob
	}{
		{
			"point-to-point uplink needs no FIB subnet route",
			"",
			true,
			append(
				[]server.NetworkJob{tunAddressJob, fibDefaultJob},
				tunRouteJobs...),
		},
		{
			"broadcast interface route keeps the FIB subnet route",
			"100.64.0.0/24",
			false,
			append(
				[]server.NetworkJob{
					tunAddressJob,
					{
						Description: "add FIB subnet route",
						Apply:       command("route add -net 100.64.0.0/24 -iface ppp0 -fib 3"),
						Reset:       command("route delete -net 100.64.0.0/24 -iface ppp0 -fib 3"),
					},
					fibDefaultJob,
				},
				tunRouteJobs...),
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			info := &tunNetworkInfoFreeBSD{
				FIBID:            3,
				GatewayIP:        "",
				PhysIfaceName:    "ppp0",
				PhysIfaceCIDR:    tc.physIfaceCIDR,
				PhysIfaceP2P:     tc.physIfaceP2P,
				TUNName:          "tun-spoofdpi",
				TunLocalIP:       "10.200.0.1",
				TunPrefixLen:     30,
				RouteTargetCIDRs: routeTargets,
				IPv6Enabled:      false,
				HasIPv6Egress:    false,
			}

			assert.Equal(t, tc.want, buildJobs(info))
		})
	}
}

// TestBuildJobs_FreeBSD_PointToPointGateway checks that a point-to-point
// uplink with a gateway keeps the FIB subnet route: its jobs are the same
// as those of any interface with a gateway.
func TestBuildJobs_FreeBSD_PointToPointGateway(t *testing.T) {
	info := &tunNetworkInfoFreeBSD{
		FIBID:            3,
		GatewayIP:        "100.64.0.254",
		PhysIfaceName:    "ppp0",
		PhysIfaceCIDR:    "100.64.0.1/32",
		PhysIfaceP2P:     true,
		TUNName:          "tun-spoofdpi",
		TunLocalIP:       "10.200.0.1",
		TunPrefixLen:     30,
		RouteTargetCIDRs: []string{"0.0.0.0/1", "128.0.0.0/1"},
		IPv6Enabled:      false,
		HasIPv6Egress:    false,
	}

	want := []server.NetworkJob{
		{
			Description: "configure TUN interface address",
			Apply:       command("ifconfig tun-spoofdpi inet 10.200.0.1/30 up"),
			Reset:       command("ifconfig tun-spoofdpi destroy"),
		},
		{
			Description: "add FIB subnet route",
			Apply:       command("route add -net 100.64.0.1/32 -iface ppp0 -fib 3"),
			Reset:       command("route delete -net 100.64.0.1/32 -iface ppp0 -fib 3"),
		},
		{
			Description: "add FIB default route",
			Apply:       command("route add default 100.64.0.254 -fib 3"),
			Reset:       command("route delete default -fib 3"),
		},
		{
			Description: "add CIDR route 0.0.0.0/1 via TUN",
			Apply:       command("route -n add -net 0.0.0.0/1 -interface tun-spoofdpi"),
			Reset:       command("route -n delete -net 0.0.0.0/1 -interface tun-spoofdpi"),
		},
		{
			Description: "add CIDR route 128.0.0.0/1 via TUN",
			Apply:       command("route -n add -net 128.0.0.0/1 -interface tun-spoofdpi"),
			Reset:       command("route -n delete -net 128.0.0.0/1 -interface tun-spoofdpi"),
		},
	}
	assert.Equal(t, want, buildJobs(info))
}
