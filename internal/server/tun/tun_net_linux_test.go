//go:build linux

package tun

import (
	"os"
	"path/filepath"
	"strings"
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
			Description: "add default route to capture table",
			Apply:       "ip route add default dev tun-spoofdpi table 200",
			Reset:       "ip route del default dev tun-spoofdpi table 200",
		},
		{
			Description: "add rule for the main table without its default route " +
				"(needs suppress_prefixlength: iproute2 and Linux 3.12+)",
			Apply: "ip rule add pref 32763 lookup main suppress_prefixlength 0",
			Reset: "ip rule del pref 32763 lookup main suppress_prefixlength 0",
		},
		{
			Description: "add policy routing rule",
			Apply:       "ip rule add pref 32764 from 192.168.1.10 lookup main",
			Reset:       "ip rule del pref 32764 from 192.168.1.10 lookup main",
		},
		{
			Description: "add capture rule for unmarked traffic",
			Apply:       "ip rule add pref 32765 fwmark 0/0xffffffff lookup 200",
			Reset:       "ip rule del pref 32765 fwmark 0/0xffffffff lookup 200",
		},
	}
	ipv6Jobs := []server.NetworkJob{
		{
			Description: "add IPv6 route 2000::/3 to capture table",
			Apply:       "ip -6 route add 2000::/3 dev tun-spoofdpi table 200",
			Reset:       "ip -6 route del 2000::/3 dev tun-spoofdpi table 200",
			Optional:    true,
			Group:       ipv6CaptureGroup,
		},
		{
			Description: "add IPv6 rule for the main table without its default " +
				"route (needs suppress_prefixlength: iproute2 and Linux 3.12+)",
			Apply:    "ip -6 rule add pref 32764 lookup main suppress_prefixlength 0",
			Reset:    "ip -6 rule del pref 32764 lookup main suppress_prefixlength 0",
			Optional: true,
			Group:    ipv6CaptureGroup,
		},
		{
			Description: "add IPv6 capture rule for unmarked traffic",
			Apply:       "ip -6 rule add pref 32765 fwmark 0/0xffffffff lookup 200",
			Reset:       "ip -6 rule del pref 32765 fwmark 0/0xffffffff lookup 200",
			Optional:    true,
			Group:       ipv6CaptureGroup,
			Warning:     ipv6RejectWarning,
		},
	}

	tcs := []struct {
		name            string
		ipv6Enabled     bool
		hasIPv6Egress   bool
		tunIPv6Disabled bool
		noIPv6Prefs     bool
		want            []server.NetworkJob
	}{
		{"ipv6 off without IPv6 egress", false, false, false, false, ipv4Jobs},
		{
			"ipv6 off with IPv6 egress adds no IPv6 jobs",
			false,
			true,
			false,
			false,
			ipv4Jobs,
		},
		{"ipv6 on without IPv6 egress", true, false, false, false, ipv4Jobs},
		{
			"ipv6 on with IPv6 egress the IPv6 jobs go last",
			true,
			true,
			false,
			false,
			append(append([]server.NetworkJob{}, ipv4Jobs...), ipv6Jobs...),
		},
		{"ipv6 on with IPv6 disabled on the TUN", true, true, true, false, ipv4Jobs},
		{"ipv6 on without IPv6 rule prefs", true, true, false, true, ipv4Jobs},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			info := &tunNetworkInfoLinux{
				CaptureTableID:      200,
				TUNName:             "tun-spoofdpi",
				PhysIfaceIP:         "192.168.1.10",
				TunLocalIP:          "10.200.0.1",
				TunRemoteIP:         "10.200.0.2",
				MainRulePref:        32763,
				FromRulePref:        32764,
				CaptureRulePref:     32765,
				IPv6MainRulePref:    32764,
				IPv6CaptureRulePref: 32765,
				IPv6Enabled:         tc.ipv6Enabled,
				HasIPv6Egress:       tc.hasIPv6Egress,
				TunIPv6Disabled:     tc.tunIPv6Disabled,
			}
			if tc.noIPv6Prefs {
				info.IPv6MainRulePref, info.IPv6CaptureRulePref = 0, 0
			}

			jobs := buildJobs(info)
			assert.Equal(t, tc.want, jobs)
			assertMainUntouched(t, jobs, info.PhysIfaceIP)
		})
	}
}

// assertMainUntouched checks that no job adds a route to the main table:
// every route goes to a numbered table, and the rules that look up main
// suppress its default route, except the one rule for traffic from
// physIP, which looks main up in full.
func assertMainUntouched(t *testing.T, jobs []server.NetworkJob, physIP string) {
	t.Helper()
	fullLookup := "from " + physIP + " lookup main"
	fullLookups := 0
	for _, j := range jobs {
		if strings.HasPrefix(j.Apply, "ip route add") ||
			strings.HasPrefix(j.Apply, "ip -6 route add") {
			assert.Contains(t, j.Apply, " table ", "route outside main: %q", j.Apply)
		}
		if !strings.Contains(j.Apply, "lookup main") {
			continue
		}
		if strings.HasPrefix(j.Apply, "ip rule add ") &&
			strings.HasSuffix(j.Apply, " "+fullLookup) {
			fullLookups++
			continue
		}
		assert.True(t,
			strings.HasSuffix(j.Apply, "lookup main suppress_prefixlength 0"),
			"rule looking up main suppresses its default: %q", j.Apply,
		)
	}
	assert.Equal(t, 1, fullLookups, "rules looking up main in full: %q", fullLookup)
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
