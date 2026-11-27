package tun

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const defaultRules = `0:	from all lookup local
32766:	from all lookup main
32767:	from all lookup default
`

func TestFreeRulePrefs(t *testing.T) {
	tcs := []struct {
		name      string
		rules     string
		n         int
		wantPrefs []int
		wantAhead []string
	}{
		{
			name:      "default rules",
			rules:     defaultRules,
			n:         3,
			wantPrefs: []int{32763, 32764, 32765},
		},
		{
			name: "tailscale rules stay ahead",
			rules: `0:	from all lookup local
5210:	from all fwmark 0x80000/0xff0000 lookup main
5230:	from all fwmark 0x80000/0xff0000 lookup default
5250:	from all fwmark 0x80000/0xff0000 unreachable
5270:	from all lookup 52
32766:	from all lookup main
32767:	from all lookup default
`,
			n:         3,
			wantPrefs: []int{32763, 32764, 32765},
		},
		{
			name: "wg-quick rules right above main",
			rules: `0:	from all lookup local
32764:	from all lookup main suppress_prefixlength 0
32765:	not from all fwmark 0xca6c lookup 51820
32766:	from all lookup main
32767:	from all lookup default
`,
			n:         3,
			wantPrefs: []int{32761, 32762, 32763},
			wantAhead: []string{
				"32764:	from all lookup main suppress_prefixlength 0",
				"32765:	not from all fwmark 0xca6c lookup 51820",
			},
		},
		{
			name: "stale spoofdpi-like rules",
			rules: `0:	from all lookup local
32763:	from all lookup main suppress_prefixlength 0
32764:	from 192.168.1.10 lookup 200
32765:	from all fwmark 0 lookup 201
32766:	from all lookup main
32767:	from all lookup default
`,
			n:         3,
			wantPrefs: []int{32760, 32761, 32762},
			wantAhead: []string{
				"32763:	from all lookup main suppress_prefixlength 0",
				"32764:	from 192.168.1.10 lookup 200",
				"32765:	from all fwmark 0 lookup 201",
			},
		},
		{
			name: "fallback skips used prefs between free ones",
			rules: `0:	from all lookup local
32762:	from all lookup 100
32765:	from all lookup 101
32766:	from all lookup main
32767:	from all lookup default
`,
			n:         3,
			wantPrefs: []int{32761, 32763, 32764},
			wantAhead: []string{
				"32762:	from all lookup 100",
				"32765:	from all lookup 101",
			},
		},
		{
			name: "main at a custom pref",
			rules: `0:	from all lookup local
100:	from all lookup 50
1000:	from all lookup main
32767:	from all lookup default
`,
			n:         3,
			wantPrefs: []int{997, 998, 999},
		},
		{
			name: "the lowest of several main rules wins",
			rules: `0:	from all lookup local
100:	from all lookup main
200:	from all lookup 50
32766:	from all lookup main
32767:	from all lookup default
`,
			n:         3,
			wantPrefs: []int{97, 98, 99},
		},
		{
			name: "main with proto kernel",
			rules: `0:	from all lookup local proto kernel
32766:	from all lookup main proto kernel
32767:	from all lookup default proto kernel
`,
			n:         3,
			wantPrefs: []int{32763, 32764, 32765},
		},
		{
			name: "garbage lines are ignored",
			rules: `Error: something odd
0:	from all lookup local

notanumber:	from all lookup 7
-5:	from all lookup 8
32766:	from all lookup main
	32765 without a colon
32767:	from all lookup default
`,
			n:         3,
			wantPrefs: []int{32763, 32764, 32765},
		},
		{
			name:      "two prefs for IPv6",
			rules:     defaultRules,
			n:         2,
			wantPrefs: []int{32764, 32765},
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
	tcs := []struct {
		name  string
		rules string
		n     int
	}{
		{
			name: "main rule missing",
			rules: `0:	from all lookup local
32766:	from all lookup main suppress_prefixlength 0
32767:	from all lookup default
`,
			n: 3,
		},
		{
			name:  "empty output",
			rules: "",
			n:     2,
		},
		{
			name: "not enough free prefs",
			rules: `0:	from all lookup local
1:	from all lookup 10
3:	from all lookup main
32767:	from all lookup default
`,
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
		assignRulePrefs([]int{32763, 32764, 32765}, []int{32764, 32765}),
	)
	assert.Equal(t,
		tunRulePrefs{main: 32763, from: 32764, capture: 32765},
		assignRulePrefs([]int{32763, 32764, 32765}, nil),
		"without IPv6 prefs the IPv6 rules get 0",
	)
}
