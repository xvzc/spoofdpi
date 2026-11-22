//go:build linux

package tun

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xvzc/spoofdpi/internal/server"
)

func TestBuildJobs_Linux(t *testing.T) {
	ipv4Jobs := []server.NetworkJob{
		{
			Description: "remove TUN interface",
			Reset:       "ip link delete tun-spoofdpi",
		},
		{
			Description: "configure TUN interface address",
			Apply:       "ip addr add 10.200.0.1 peer 10.200.0.2 dev tun-spoofdpi",
			Reset:       "ip addr del 10.200.0.1 peer 10.200.0.2 dev tun-spoofdpi",
		},
		{
			Description: "bring TUN interface up",
			Apply:       "ip link set dev tun-spoofdpi up",
			Reset:       "ip link set dev tun-spoofdpi down",
		},
		{
			Description: "add gateway host route",
			Apply:       "ip route add 192.168.1.1 dev eth0",
			Reset:       "ip route del 192.168.1.1 dev eth0",
		},
		{
			Description: "add default route to routing table",
			Apply:       "ip route add default via 192.168.1.1 dev eth0 table 200",
			Reset:       "ip route del default table 200",
		},
		{
			Description: "add policy routing rule",
			Apply:       "ip rule add from 192.168.1.10 lookup 200",
			Reset:       "ip rule del from 192.168.1.10 lookup 200",
		},
		{
			Description: "add CIDR route 10.200.0.0/30 via TUN",
			Apply:       "ip route add 10.200.0.0/30 dev tun-spoofdpi",
			Reset:       "ip route del 10.200.0.0/30 dev tun-spoofdpi",
		},
		{
			Description: "add CIDR route 0.0.0.0/1 via TUN",
			Apply:       "ip route add 0.0.0.0/1 dev tun-spoofdpi",
			Reset:       "ip route del 0.0.0.0/1 dev tun-spoofdpi",
		},
		{
			Description: "add CIDR route 128.0.0.0/1 via TUN",
			Apply:       "ip route add 128.0.0.0/1 dev tun-spoofdpi",
			Reset:       "ip route del 128.0.0.0/1 dev tun-spoofdpi",
		},
	}
	ipv6Job := server.NetworkJob{
		Description: "add IPv6 route 2000::/3 via TUN",
		Apply:       "ip -6 route add 2000::/3 dev tun-spoofdpi",
		Reset:       "ip -6 route del 2000::/3 dev tun-spoofdpi",
		Optional:    true,
		Warning:     ipv6RejectWarning,
	}

	tcs := []struct {
		name            string
		hasIPv6Egress   bool
		tunIPv6Disabled bool
		want            []server.NetworkJob
	}{
		{"without IPv6 egress", false, false, ipv4Jobs},
		{
			"with IPv6 egress the IPv6 route goes last",
			true,
			false,
			append(ipv4Jobs, ipv6Job),
		},
		{"with IPv6 disabled on the TUN", true, true, ipv4Jobs},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			info := &tunNetworkInfoLinux{
				RouteTableID:  200,
				GatewayIP:     "192.168.1.1",
				TUNName:       "tun-spoofdpi",
				PhysIfaceName: "eth0",
				PhysIfaceIP:   "192.168.1.10",
				TunLocalIP:    "10.200.0.1",
				TunRemoteIP:   "10.200.0.2",
				RouteTargetCIDRs: []string{
					"10.200.0.0/30",
					"0.0.0.0/1",
					"128.0.0.0/1",
				},
				HasIPv6Egress:   tc.hasIPv6Egress,
				TunIPv6Disabled: tc.tunIPv6Disabled,
			}

			assert.Equal(t, tc.want, buildJobs(info))
		})
	}
}

func TestIPv6Disabled(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}

	assert.True(t, ipv6Disabled(write("disabled", "1\n")))
	assert.False(t, ipv6Disabled(write("enabled", "0\n")))
	assert.False(t, ipv6Disabled(filepath.Join(dir, "missing")))
}
