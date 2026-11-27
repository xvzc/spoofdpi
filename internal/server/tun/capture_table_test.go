package tun

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/route"
)

func TestFreeCaptureTable(t *testing.T) {
	table, err := freeCaptureTable(defaultRules, []route.RouteEntry{mainRoute()})
	require.NoError(t, err)
	assert.Equal(t, captureTableFirst, table)

	ipv6Route := captureRoute(netutil.FamilyV6, captureTableFirst, 3)
	ruleOfSecond := lookupRule(100, captureTableFirst+1)
	table, err = freeCaptureTable(
		append([]route.Rule{ruleOfSecond}, defaultRules...),
		[]route.RouteEntry{ipv6Route},
	)
	require.NoError(t, err)
	assert.Equal(t, captureTableFirst+2, table,
		"a table with an IPv6 route or a rule that looks it up is taken")

	var full []route.RouteEntry
	for id := captureTableFirst; id <= captureTableLast; id++ {
		full = append(full, captureRoute(netutil.FamilyV4, id, 3))
	}
	_, err = freeCaptureTable(nil, full)
	assert.Error(t, err)
}

func TestIPRuleCommand(t *testing.T) {
	src := lookupRule(100, 300)
	src.Src = netip.MustParsePrefix("10.0.0.0/8")
	src.TOS = 0x10

	tcs := []struct {
		rule route.Rule
		want string
	}{
		{
			captureRule(netutil.FamilyV4, 32765, captureTableFirst),
			"ip rule del pref 32765 fwmark 0/0xffffffff lookup 1397769216 protocol 213",
		},
		{
			dumpedRule(captureRule(netutil.FamilyV6, 32765, captureTableFirst)),
			"ip -6 rule del pref 32765 fwmark 0/0xffffffff lookup 1397769216 protocol 213",
		},
		{src, "ip rule del pref 100 from 10.0.0.0/8 tos 0x10 lookup 300"},
	}
	for _, tc := range tcs {
		assert.Equal(t, tc.want, ipRuleCommand("del", tc.rule))
	}
}

func TestIPRouteCommand(t *testing.T) {
	assert.Equal(t,
		"ip route add default dev tun-spoofdpi table 1397769216 proto 213",
		ipRouteCommand("add",
			captureRoute(netutil.FamilyV4, captureTableFirst, 3), "tun-spoofdpi"),
	)
	assert.Equal(t,
		"ip -6 route del 2000::/3 table 1397769216 proto 213",
		ipRouteCommand("del", captureRoute(netutil.FamilyV6, captureTableFirst, 3), ""),
	)
	assert.Equal(t,
		"ip route del default via 192.168.1.1 table main proto 16",
		ipRouteCommand("del", mainRoute(), ""),
	)
}

func TestIsCaptureRouteShape(t *testing.T) {
	assert.True(t, isCaptureRouteShape(captureRoute(netutil.FamilyV4, tableA, 0)))
	assert.True(t, isCaptureRouteShape(captureRoute(netutil.FamilyV6, tableA, 0)))
	assert.False(t, isCaptureRouteShape(mainRoute()), "a route through a gateway")

	narrow := captureRoute(netutil.FamilyV4, tableA, 0)
	narrow.Dst = netip.MustParsePrefix("10.0.0.0/8")
	assert.False(t, isCaptureRouteShape(narrow))

	ipv6Default := captureRoute(netutil.FamilyV6, tableA, 0)
	ipv6Default.Dst = netip.MustParsePrefix("::/0")
	assert.False(t, isCaptureRouteShape(ipv6Default))
}
