package tun

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/route"
)

// lookupRule returns the IPv4 rule `pref: from all lookup table`.
func lookupRule(pref, table uint32) route.Rule {
	return route.Rule{
		Family:   netutil.FamilyV4,
		Priority: pref,
		Table:    table,
		Action:   route.RuleActionToTable,
	}
}

// markRule returns the IPv4 rule `pref: from all fwmark mark/mask lookup
// table`.
func markRule(pref, mark, mask, table uint32) route.Rule {
	r := lookupRule(pref, table)
	r.Fwmark, r.HasFwmark = mark, mark != 0
	r.Fwmask, r.HasFwmask = mask, true
	return r
}

// defaultRules are the rules of a host without policy routing: local,
// main and default.
var defaultRules = []route.Rule{
	lookupRule(0, 255),
	lookupRule(32766, mainTable),
	lookupRule(32767, 253),
}

func TestFreeRulePrefs(t *testing.T) {
	wgMain := lookupRule(32764, mainTable)
	wgMain.SuppressPrefixlen, wgMain.HasSuppressPrefixlen = 0, true
	wgCapture := markRule(32765, 0xca6c, 0xffffffff, 51820)
	wgCapture.Invert = true

	staleMain := lookupRule(32763, mainTable)
	staleMain.SuppressPrefixlen, staleMain.HasSuppressPrefixlen = 0, true
	staleFrom := lookupRule(32764, 200)
	staleFrom.Src = netip.MustParsePrefix("192.168.1.10/32")
	staleCapture := markRule(32765, 0, 0xffffffff, 201)

	kernelMain := lookupRule(32766, mainTable)
	kernelMain.Protocol, kernelMain.HasProtocol = 2, true

	markedMain := markRule(100, 0x80000, 0xff0000, mainTable)
	unreachable := lookupRule(5250, 0)
	unreachable.Action = 6

	tcs := []struct {
		name      string
		rules     []route.Rule
		n         int
		wantPrefs []uint32
		wantAhead []route.Rule
	}{
		{
			name:      "default rules",
			rules:     defaultRules,
			n:         3,
			wantPrefs: []uint32{32763, 32764, 32765},
		},
		{
			name: "tailscale rules stay ahead",
			rules: []route.Rule{
				lookupRule(0, 255),
				markRule(5210, 0x80000, 0xff0000, mainTable),
				markRule(5230, 0x80000, 0xff0000, 253),
				unreachable,
				lookupRule(5270, 52),
				lookupRule(32766, mainTable),
				lookupRule(32767, 253),
			},
			n:         3,
			wantPrefs: []uint32{32763, 32764, 32765},
		},
		{
			name: "wg-quick rules right above main",
			rules: []route.Rule{
				lookupRule(0, 255),
				wgMain,
				wgCapture,
				lookupRule(32766, mainTable),
				lookupRule(32767, 253),
			},
			n:         3,
			wantPrefs: []uint32{32761, 32762, 32763},
			wantAhead: []route.Rule{wgMain, wgCapture},
		},
		{
			name: "stale spoofdpi-like rules",
			rules: []route.Rule{
				lookupRule(0, 255),
				staleMain,
				staleFrom,
				staleCapture,
				lookupRule(32766, mainTable),
				lookupRule(32767, 253),
			},
			n:         3,
			wantPrefs: []uint32{32760, 32761, 32762},
			wantAhead: []route.Rule{staleMain, staleFrom, staleCapture},
		},
		{
			name: "fallback takes a consecutive block",
			rules: []route.Rule{
				lookupRule(0, 255),
				lookupRule(32762, 100),
				lookupRule(32765, 101),
				lookupRule(32766, mainTable),
				lookupRule(32767, 253),
			},
			n:         3,
			wantPrefs: []uint32{32759, 32760, 32761},
			wantAhead: []route.Rule{lookupRule(32762, 100), lookupRule(32765, 101)},
		},
		{
			name: "fallback uses a gap that is just large enough",
			rules: []route.Rule{
				lookupRule(0, 255),
				lookupRule(32761, 100),
				lookupRule(32765, 101),
				lookupRule(32766, mainTable),
			},
			n:         3,
			wantPrefs: []uint32{32762, 32763, 32764},
			wantAhead: []route.Rule{lookupRule(32765, 101)},
		},
		{
			name: "main at a custom pref",
			rules: []route.Rule{
				lookupRule(0, 255),
				lookupRule(100, 50),
				lookupRule(1000, mainTable),
				lookupRule(32767, 253),
			},
			n:         3,
			wantPrefs: []uint32{997, 998, 999},
		},
		{
			name: "the lowest of several main rules wins",
			rules: []route.Rule{
				lookupRule(0, 255),
				lookupRule(100, mainTable),
				lookupRule(200, 50),
				lookupRule(32766, mainTable),
				lookupRule(32767, 253),
			},
			n:         3,
			wantPrefs: []uint32{97, 98, 99},
		},
		{
			name: "a rule for marked packets is not the main rule",
			rules: []route.Rule{
				lookupRule(0, 255),
				markedMain,
				lookupRule(32766, mainTable),
			},
			n:         3,
			wantPrefs: []uint32{32763, 32764, 32765},
		},
		{
			name: "main with a protocol",
			rules: []route.Rule{
				lookupRule(0, 255),
				kernelMain,
				lookupRule(32767, 253),
			},
			n:         3,
			wantPrefs: []uint32{32763, 32764, 32765},
		},
		{
			name:      "two prefs for IPv6",
			rules:     defaultRules,
			n:         2,
			wantPrefs: []uint32{32764, 32765},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			prefs, ahead, err := freeRulePrefs(tc.rules, tc.n)
			require.NoError(t, err)
			assert.Equal(t, tc.wantPrefs, prefs)
			assert.Equal(t, tc.wantAhead, ahead)
		})
	}
}

func TestFreeRulePrefs_Errors(t *testing.T) {
	suppressedMain := lookupRule(32766, mainTable)
	suppressedMain.SuppressPrefixlen, suppressedMain.HasSuppressPrefixlen = 0, true

	tcs := []struct {
		name  string
		rules []route.Rule
		n     int
	}{
		{
			name:  "main rule missing",
			rules: []route.Rule{lookupRule(0, 255), suppressedMain, lookupRule(32767, 253)},
			n:     3,
		},
		{
			name:  "no rules",
			rules: nil,
			n:     2,
		},
		{
			name: "not enough free prefs",
			rules: []route.Rule{
				lookupRule(0, 255),
				lookupRule(1, 10),
				lookupRule(3, mainTable),
			},
			n: 2,
		},
		{
			name: "free prefs are not consecutive",
			rules: []route.Rule{
				lookupRule(0, 255),
				lookupRule(2, 10),
				lookupRule(4, 11),
				lookupRule(5, mainTable),
			},
			n: 2,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := freeRulePrefs(tc.rules, tc.n)
			assert.Error(t, err)
		})
	}
}

func TestAssignRulePrefs(t *testing.T) {
	assert.Equal(t,
		tunRulePrefs{
			main:        32763,
			from:        32764,
			capture:     32765,
			ipv6Main:    32764,
			ipv6Capture: 32765,
		},
		assignRulePrefs([]uint32{32763, 32764, 32765}, []uint32{32764, 32765}),
	)
	assert.Equal(t,
		tunRulePrefs{main: 32763, from: 32764, capture: 32765},
		assignRulePrefs([]uint32{32763, 32764, 32765}, nil),
		"without IPv6 prefs the IPv6 rules get 0",
	)
}
