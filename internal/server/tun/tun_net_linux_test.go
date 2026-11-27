//go:build linux

package tun

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/route"
	"github.com/xvzc/spoofdpi/internal/server"
)

func TestBuildJobs_Linux(t *testing.T) {
	const table = 0x53504400
	ipv4Strings := [][3]string{
		{
			"configure TUN interface address",
			"ip addr add 10.200.0.1 peer 10.200.0.2 dev tun-spoofdpi",
			"ip addr del 10.200.0.1 peer 10.200.0.2 dev tun-spoofdpi",
		},
		{
			"bring TUN interface up",
			"ip link set dev tun-spoofdpi up",
			"ip link set dev tun-spoofdpi down",
		},
		{
			"add capture rule for unmarked traffic",
			"ip rule add pref 32765 fwmark 0/0xffffffff lookup 1397769216 protocol 213",
			"ip rule del pref 32765 fwmark 0/0xffffffff lookup 1397769216 protocol 213",
		},
		{
			"add rule for the main table without its default route",
			"ip rule add pref 32763 lookup main suppress_prefixlength 0 protocol 213",
			"ip rule del pref 32763 lookup main suppress_prefixlength 0 protocol 213",
		},
		{
			"add policy routing rule",
			"ip rule add pref 32764 from 192.168.1.10 lookup main protocol 213",
			"ip rule del pref 32764 from 192.168.1.10 lookup main protocol 213",
		},
		{
			"add default route to capture table",
			"ip route add default dev tun-spoofdpi table 1397769216 proto 213",
			"ip route del default dev tun-spoofdpi table 1397769216 proto 213",
		},
	}
	ipv6Strings := [][3]string{
		{
			"add IPv6 capture rule for unmarked traffic",
			"ip -6 rule add pref 32765 fwmark 0/0xffffffff lookup 1397769216 protocol 213",
			"ip -6 rule del pref 32765 fwmark 0/0xffffffff lookup 1397769216 protocol 213",
		},
		{
			"add IPv6 rule for the main table without its default route",
			"ip -6 rule add pref 32764 lookup main suppress_prefixlength 0 protocol 213",
			"ip -6 rule del pref 32764 lookup main suppress_prefixlength 0 protocol 213",
		},
		{
			"add IPv6 route 2000::/3 to capture table",
			"ip -6 route add 2000::/3 dev tun-spoofdpi table 1397769216 proto 213",
			"ip -6 route del 2000::/3 dev tun-spoofdpi table 1397769216 proto 213",
		},
	}
	withIPv6 := append(append([][3]string{}, ipv4Strings...), ipv6Strings...)

	tcs := []struct {
		name            string
		ipv6Enabled     bool
		hasIPv6Egress   bool
		tunIPv6Disabled bool
		noIPv6Prefs     bool
		want            [][3]string
	}{
		{"ipv6 off without IPv6 egress", false, false, false, false, ipv4Strings},
		{
			"ipv6 off with IPv6 egress adds no IPv6 jobs",
			false,
			true,
			false,
			false,
			ipv4Strings,
		},
		{"ipv6 on without IPv6 egress", true, false, false, false, ipv4Strings},
		{
			"ipv6 on with IPv6 egress the IPv6 jobs go last",
			true,
			true,
			false,
			false,
			withIPv6,
		},
		{"ipv6 on with IPv6 disabled on the TUN", true, true, true, false, ipv4Strings},
		{"ipv6 on without IPv6 rule prefs", true, true, false, true, ipv4Strings},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			info := &tunNetworkInfoLinux{
				CaptureTableID:      table,
				TUNName:             "tun-spoofdpi",
				TUNIndex:            7,
				PhysIfaceIP:         netip.MustParseAddr("192.168.1.10"),
				TunLocalIP:          netip.MustParseAddr("10.200.0.1"),
				TunRemoteIP:         netip.MustParseAddr("10.200.0.2"),
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
			got := make([][3]string, 0, len(jobs))
			for _, j := range jobs {
				got = append(got, [3]string{j.Description, j.Apply.String(), j.Reset.String()})
			}
			assert.Equal(t, tc.want, got)
			assertJobsTagged(t, jobs)
			assertMainUntouched(t, jobs, info.PhysIfaceIP)
			assertResetUndoesApply(t, jobs)
			assertIPv6Group(t, jobs)
		})
	}
}

func TestBuildJobs_Linux_Values(t *testing.T) {
	info := &tunNetworkInfoLinux{
		CaptureTableID:      0x53504401,
		TUNName:             "tun-spoofdpi",
		TUNIndex:            7,
		PhysIfaceIP:         netip.MustParseAddr("192.168.1.10"),
		TunLocalIP:          netip.MustParseAddr("10.200.0.1"),
		TunRemoteIP:         netip.MustParseAddr("10.200.0.2"),
		MainRulePref:        32763,
		FromRulePref:        32764,
		CaptureRulePref:     32765,
		IPv6MainRulePref:    32764,
		IPv6CaptureRulePref: 32765,
		IPv6Enabled:         true,
		HasIPv6Egress:       true,
		TunIPv6Disabled:     false,
	}
	jobs := buildJobs(info)
	require.Len(t, jobs, 9)

	assert.Equal(t, addressAction{
		add: true,
		addr: route.InterfaceAddr{
			Index:     7,
			Local:     netip.MustParseAddr("10.200.0.1"),
			Peer:      netip.MustParseAddr("10.200.0.2"),
			PrefixLen: 32,
		},
		dev: "tun-spoofdpi",
	}, jobs[0].Apply)
	assert.Equal(t, linkAction{up: true, index: 7, dev: "tun-spoofdpi"}, jobs[1].Apply)
	assert.Equal(t, ruleAction{add: true, rule: route.Rule{
		Family:      netutil.FamilyV4,
		Priority:    32765,
		Table:       0x53504401,
		Action:      route.RuleActionToTable,
		HasFwmark:   true,
		Fwmask:      0xffffffff,
		HasFwmask:   true,
		Protocol:    213,
		HasProtocol: true,
	}}, jobs[2].Apply)
	assert.Equal(t, routeAction{add: true, entry: route.RouteEntry{
		Table:    0x53504401,
		Dst:      netip.MustParsePrefix("0.0.0.0/0"),
		Oif:      7,
		Protocol: 213,
		Scope:    route.RouteScopeLink,
		Type:     route.RouteTypeUnicast,
	}, dev: "tun-spoofdpi"}, jobs[5].Apply)
	assert.Equal(t, routeAction{add: true, entry: route.RouteEntry{
		Table:    0x53504401,
		Dst:      netip.MustParsePrefix("2000::/3"),
		Oif:      7,
		Protocol: 213,
		Scope:    route.RouteScopeUniverse,
		Type:     route.RouteTypeUnicast,
	}, dev: "tun-spoofdpi"}, jobs[8].Apply)
	assert.Equal(t, ipv6RejectWarning, jobs[8].Warning,
		"the warning comes once capture starts, with the route")
}

// assertJobsTagged checks that every rule and route the jobs add carries
// TUN mode's tag, and that every rule the capture table goes with is in
// it, so the leftover search can find them.
func assertJobsTagged(t *testing.T, jobs []server.NetworkJob) {
	t.Helper()
	for _, j := range jobs {
		switch a := j.Apply.(type) {
		case ruleAction:
			assert.True(t, isTagged(a.rule), "untagged rule: %s", a)
		case routeAction:
			assert.Equal(t, captureProtocol, a.entry.Protocol, "untagged route: %s", a)
			assert.True(t, inCaptureTableRange(a.entry.Table), "route table: %s", a)
		}
	}
}

// assertMainUntouched checks that no job adds a route to the main table:
// every route goes to the capture table, and the rules that look up main
// suppress its default route, except the one rule for traffic from
// physIP, which looks main up in full.
func assertMainUntouched(t *testing.T, jobs []server.NetworkJob, physIP netip.Addr) {
	t.Helper()
	fullLookups := 0
	for _, j := range jobs {
		switch a := j.Apply.(type) {
		case routeAction:
			assert.NotEqual(t, mainTable, a.entry.Table, "route in main: %s", a)
		case ruleAction:
			if a.rule.Table != mainTable {
				continue
			}
			if isFromShape(a.rule) && a.rule.Src.Addr() == physIP {
				fullLookups++
				continue
			}
			assert.True(t, isMainLookupShape(a.rule),
				"rule looking up main suppresses its default: %s", a)
		}
	}
	assert.Equal(t, 1, fullLookups, "rules looking up main in full from %s", physIP)
}

// assertResetUndoesApply checks that each job's Reset deletes what its
// Apply adds.
func assertResetUndoesApply(t *testing.T, jobs []server.NetworkJob) {
	t.Helper()
	for _, j := range jobs {
		switch a := j.Apply.(type) {
		case ruleAction:
			assert.Equal(t, ruleAction{add: false, rule: a.rule}, j.Reset, j.Description)
		case routeAction:
			assert.Equal(t,
				routeAction{add: false, entry: a.entry, dev: a.dev}, j.Reset, j.Description)
		case addressAction:
			assert.Equal(t,
				addressAction{add: false, addr: a.addr, dev: a.dev}, j.Reset, j.Description)
		case linkAction:
			assert.Equal(t,
				linkAction{up: false, index: a.index, dev: a.dev}, j.Reset, j.Description)
		default:
			t.Errorf("%s: unexpected action %T", j.Description, j.Apply)
		}
	}
}

// assertIPv6Group checks that the IPv6 jobs, and only they, are optional
// and in ipv6CaptureGroup.
func assertIPv6Group(t *testing.T, jobs []server.NetworkJob) {
	t.Helper()
	for _, j := range jobs {
		ipv6 := strings.Contains(j.Description, "IPv6")
		assert.Equal(t, ipv6, j.Optional, j.Description)
		if ipv6 {
			assert.Equal(t, ipv6CaptureGroup, j.Group, j.Description)
		} else {
			assert.Empty(t, j.Group, j.Description)
		}
	}
}

func TestCheckRuleProtocol(t *testing.T) {
	release := func() string { return "4.14.0-test" }
	someRules := func() ([]route.Rule, error) { return defaultRules, nil }
	supported := func(ok bool) func() (bool, error) {
		return func() (bool, error) { return ok, nil }
	}

	tcs := []struct {
		name      string
		rules     func() ([]route.Rule, error)
		supported func() (bool, error)
		want      []string
	}{
		{name: "tags kept", rules: someRules, supported: supported(true)},
		{
			name:      "tags dropped",
			rules:     someRules,
			supported: supported(false),
			want:      []string{"4.17", "4.14.0-test"},
		},
		{
			name: "no policy routing",
			rules: func() ([]route.Rule, error) {
				return nil, fmt.Errorf("rules: %w", syscall.EAFNOSUPPORT)
			},
			supported: supported(false),
			want:      []string{"CONFIG_IP_MULTIPLE_TABLES", "4.14.0-test"},
		},
		{
			name:      "dump failed",
			rules:     func() ([]route.Rule, error) { return nil, errors.New("dump failed") },
			supported: supported(false),
			want:      []string{"dump failed"},
		},
		{
			name:      "no IPv4 rules",
			rules:     func() ([]route.Rule, error) { return nil, nil },
			supported: supported(false),
			want:      []string{"shows none", "4.14.0-test"},
		},
		{
			name:  "support check failed",
			rules: someRules,
			supported: func() (bool, error) {
				return false, errors.New("check failed")
			},
			want: []string{"check failed"},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			err := checkRuleProtocol(tc.rules, tc.supported, release)
			if tc.want == nil {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			for _, w := range tc.want {
				assert.Contains(t, err.Error(), w)
			}
		})
	}
}

func TestTUNFlagsPersistent(t *testing.T) {
	persistent, err := tunFlagsPersistent("0x1002\n")
	require.NoError(t, err)
	assert.False(t, persistent)

	persistent, err = tunFlagsPersistent("0x1802\n")
	require.NoError(t, err)
	assert.True(t, persistent)

	_, err = tunFlagsPersistent("garbage")
	assert.Error(t, err)
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
