package route

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/netutil"
)

// nlRuleHdr encodes a fib_rule_hdr followed by attrs.
func nlRuleHdr(
	family, srcLen, table, action uint8,
	flags uint32,
	attrs ...[]byte,
) []byte {
	b := []byte{family, 0, srcLen, 0, table, 0, 0, action}
	b = append(b, nlU32(flags)...)
	for _, a := range attrs {
		b = append(b, a...)
	}
	return b
}

func nlU8Attr(typ uint16, v uint8) []byte { return nlAttr(typ, []byte{v}) }

// The rules spoofdpi's Linux TUN mode sets, tagged with protocol 213.
var (
	ruleP1 = Rule{
		Family:               netutil.FamilyV4,
		Priority:             32763,
		Table:                254,
		Action:               RuleActionToTable,
		SuppressPrefixlen:    0,
		HasSuppressPrefixlen: true,
		Protocol:             213,
		HasProtocol:          true,
	}
	ruleP2 = Rule{
		Family:      netutil.FamilyV4,
		Priority:    32764,
		Table:       254,
		Action:      RuleActionToTable,
		Src:         netip.MustParsePrefix("192.168.1.10/32"),
		Protocol:    213,
		HasProtocol: true,
	}
	ruleP3 = Rule{
		Family:      netutil.FamilyV4,
		Priority:    32765,
		Table:       0x53504401,
		Action:      RuleActionToTable,
		Fwmask:      0xffffffff,
		HasFwmask:   true,
		Protocol:    213,
		HasProtocol: true,
	}
)

func TestEncodeRuleModify(t *testing.T) {
	tcs := []struct {
		name      string
		rule      Rule
		add       bool
		wantTyp   uint16
		wantFlags uint16
		wantHdr   []byte
		wantAttrs [][]byte
	}{
		{
			name:      "add P3 sends the mask of a zero mark",
			rule:      ruleP3,
			add:       true,
			wantTyp:   rtmNewRule,
			wantFlags: addFlags,
			wantHdr:   nlRuleHdr(linuxAFInet, 0, 0, frActToTbl, 0),
			wantAttrs: [][]byte{
				nlAttr(fraPriority, nlU32(32765)),
				nlAttr(fraTable, nlU32(0x53504401)),
				nlAttr(fraFwmask, nlU32(0xffffffff)),
				nlU8Attr(fraProtocol, 213),
			},
		},
		{
			name:      "delete P3 carries pref, table, mask and protocol",
			rule:      ruleP3,
			wantTyp:   rtmDelRule,
			wantFlags: delFlags,
			wantHdr:   nlRuleHdr(linuxAFInet, 0, 0, frActToTbl, 0),
			wantAttrs: [][]byte{
				nlAttr(fraPriority, nlU32(32765)),
				nlAttr(fraTable, nlU32(0x53504401)),
				nlAttr(fraFwmask, nlU32(0xffffffff)),
				nlU8Attr(fraProtocol, 213),
			},
		},
		{
			name:      "add P1 with suppress_prefixlength 0",
			rule:      ruleP1,
			add:       true,
			wantTyp:   rtmNewRule,
			wantFlags: addFlags,
			wantHdr:   nlRuleHdr(linuxAFInet, 0, 0, frActToTbl, 0),
			wantAttrs: [][]byte{
				nlAttr(fraPriority, nlU32(32763)),
				nlAttr(fraTable, nlU32(254)),
				nlAttr(fraSuppressPrefixlen, nlU32(0)),
				nlU8Attr(fraProtocol, 213),
			},
		},
		{
			name:      "add P2 with a source",
			rule:      ruleP2,
			add:       true,
			wantTyp:   rtmNewRule,
			wantFlags: addFlags,
			wantHdr:   nlRuleHdr(linuxAFInet, 32, 0, frActToTbl, 0),
			wantAttrs: [][]byte{
				nlAttr(fraPriority, nlU32(32764)),
				nlAttr(fraTable, nlU32(254)),
				nlAttr(fraSrc, nlAddr("192.168.1.10")),
				nlU8Attr(fraProtocol, 213),
			},
		},
		{
			name: "add ipv6 inverted mark with defaults",
			rule: Rule{
				Family:    netutil.FamilyV6,
				Priority:  100,
				Table:     51820,
				Invert:    true,
				Fwmark:    0xca6c,
				HasFwmark: true,
			},
			add:       true,
			wantTyp:   rtmNewRule,
			wantFlags: addFlags,
			wantHdr:   nlRuleHdr(linuxAFInet6, 0, 0, frActToTbl, fibRuleInvert),
			wantAttrs: [][]byte{
				nlAttr(fraPriority, nlU32(100)),
				nlAttr(fraTable, nlU32(51820)),
				nlAttr(fraFwmark, nlU32(0xca6c)),
			},
		},
		{
			name:      "delete keeps a zero action",
			rule:      Rule{Family: netutil.FamilyV6, Priority: 100},
			wantTyp:   rtmDelRule,
			wantFlags: delFlags,
			wantHdr:   nlRuleHdr(linuxAFInet6, 0, 0, 0, 0),
			wantAttrs: [][]byte{
				nlAttr(fraPriority, nlU32(100)),
				nlAttr(fraTable, nlU32(0)),
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			m := parseOneRequest(t, encodeRuleModify(13, tc.rule, tc.add))
			assert.Equal(t, tc.wantTyp, m.typ)
			assert.Equal(t, tc.wantFlags, m.flags)
			assert.Equal(t, uint32(13), m.seq)
			require.GreaterOrEqual(t, len(m.data), fibRuleHdrLen)
			assert.Equal(t, tc.wantHdr, m.data[:fibRuleHdrLen])
			var wantAttrs []byte
			for _, a := range tc.wantAttrs {
				wantAttrs = append(wantAttrs, a...)
			}
			assert.Equal(t, wantAttrs, m.data[fibRuleHdrLen:])
		})
	}
}

func TestEncodeRuleDump(t *testing.T) {
	m := parseOneRequest(t, encodeRuleDump(3, netutil.FamilyV6))
	assert.Equal(t, uint16(rtmGetRule), m.typ)
	assert.Equal(t, uint16(nlmFRequest|nlmFDump), m.flags)
	assert.Equal(t, uint32(3), m.seq)
	assert.Equal(t, nlRuleHdr(linuxAFInet6, 0, 0, 0, 0), m.data)
}

func TestRulesFromNetlink(t *testing.T) {
	msg := func(payload []byte) netlinkMessage {
		return netlinkMessage{typ: rtmNewRule, data: payload}
	}
	unsetSuppress := nlAttr(fraSuppressPrefixlen, nlU32(suppressPrefixlenUnset))

	tcs := []struct {
		name  string
		fam   netutil.Family
		reply []netlinkMessage
		want  []Rule
	}{
		{
			name: "4.17+ kernel defaults and P1 to P3",
			fam:  netutil.FamilyV4,
			reply: []netlinkMessage{
				// 0: from all lookup local; pref 0 has no FRA_PRIORITY.
				msg(nlRuleHdr(linuxAFInet, 0, 255, frActToTbl, 0,
					nlAttr(fraTable, nlU32(255)),
					unsetSuppress,
					nlU8Attr(fraProtocol, 2),
				)),
				msg(nlRuleHdr(linuxAFInet, 0, 254, frActToTbl, 0,
					nlAttr(fraTable, nlU32(254)),
					nlAttr(fraSuppressPrefixlen, nlU32(0)),
					nlU8Attr(fraProtocol, 213),
					nlAttr(fraPriority, nlU32(32763)),
				)),
				msg(nlRuleHdr(linuxAFInet, 32, 254, frActToTbl, 0,
					nlAttr(fraTable, nlU32(254)),
					unsetSuppress,
					nlU8Attr(fraProtocol, 213),
					nlAttr(fraPriority, nlU32(32764)),
					nlAttr(fraSrc, nlAddr("192.168.1.10")),
				)),
				// The kernel dumps the mask of a zero mark, not the mark.
				msg(nlRuleHdr(linuxAFInet, 0, 252, frActToTbl, 0,
					nlAttr(fraTable, nlU32(0x53504401)),
					unsetSuppress,
					nlU8Attr(fraProtocol, 213),
					nlAttr(fraPriority, nlU32(32765)),
					nlAttr(fraFwmask, nlU32(0xffffffff)),
				)),
				// Another family and other message types are skipped.
				msg(nlRuleHdr(linuxAFInet6, 0, 254, frActToTbl, 0)),
				{typ: rtmNewRoute, data: nlRuleHdr(linuxAFInet, 0, 1, 0, 0)},
			},
			want: []Rule{
				{
					Family:      netutil.FamilyV4,
					Table:       255,
					Action:      RuleActionToTable,
					Protocol:    2,
					HasProtocol: true,
				},
				ruleP1,
				ruleP2,
				ruleP3,
			},
		},
		{
			name: "pre-4.17 kernel without FRA_PROTOCOL",
			fam:  netutil.FamilyV4,
			reply: []netlinkMessage{
				msg(nlRuleHdr(linuxAFInet, 0, 254, frActToTbl, 0,
					nlAttr(fraTable, nlU32(254)),
					unsetSuppress,
					nlAttr(fraPriority, nlU32(32766)),
				)),
			},
			want: []Rule{{
				Family:   netutil.FamilyV4,
				Priority: 32766,
				Table:    254,
				Action:   RuleActionToTable,
			}},
		},
		{
			name: "wg-quick rules: inverted mark without mask, and a nonzero mask",
			fam:  netutil.FamilyV6,
			reply: []netlinkMessage{
				msg(nlRuleHdr(linuxAFInet6, 0, 252, frActToTbl, fibRuleInvert,
					nlAttr(fraTable, nlU32(51820)),
					unsetSuppress,
					nlU8Attr(fraProtocol, 4),
					nlAttr(fraPriority, nlU32(32765)),
					nlAttr(fraFwmark, nlU32(0xca6c)),
					nlAttr(fraFwmask, nlU32(0xffffffff)),
				)),
				msg(nlRuleHdr(linuxAFInet6, 0, 0, frActToTbl, 0,
					nlAttr(fraPriority, nlU32(100)),
					nlAttr(fraFwmark, nlU32(0x1)),
					nlAttr(fraFwmask, nlU32(0xff)),
				)),
			},
			want: []Rule{
				{
					Family:      netutil.FamilyV6,
					Priority:    32765,
					Table:       51820,
					Action:      RuleActionToTable,
					Invert:      true,
					Fwmark:      0xca6c,
					HasFwmark:   true,
					Fwmask:      0xffffffff,
					HasFwmask:   true,
					Protocol:    4,
					HasProtocol: true,
				},
				{
					Family:    netutil.FamilyV6,
					Priority:  100,
					Action:    RuleActionToTable,
					Fwmark:    0x1,
					HasFwmark: true,
					Fwmask:    0xff,
					HasFwmask: true,
				},
			},
		},
		{
			name: "ipv6 source and other selectors",
			fam:  netutil.FamilyV6,
			reply: []netlinkMessage{
				msg(nlRuleHdr(linuxAFInet6, 64, 254, frActToTbl, 0,
					nlAttr(fraPriority, nlU32(200)),
					nlAttr(fraSrc, nlAddr("2001:db8::")),
					nlAttr(3, []byte("eth0\x00")), // FRA_IIFNAME
					nlAttr(20, make([]byte, 8)),   // FRA_UID_RANGE
					unsetSuppress,
					nlU8Attr(fraProtocol, 0),
				)),
			},
			want: []Rule{{
				Family:      netutil.FamilyV6,
				Priority:    200,
				Table:       254,
				Action:      RuleActionToTable,
				Src:         netip.MustParsePrefix("2001:db8::/64"),
				HasProtocol: true,
				OtherAttrs:  []uint16{3, 20},
			}},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got, err := rulesFromNetlink(tc.reply, tc.fam)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}

	t.Run("short message", func(t *testing.T) {
		_, err := rulesFromNetlink([]netlinkMessage{msg([]byte{linuxAFInet, 0})},
			netutil.FamilyV4)
		assert.Error(t, err)
	})
	t.Run("source of another family", func(t *testing.T) {
		_, err := rulesFromNetlink([]netlinkMessage{msg(nlRuleHdr(linuxAFInet, 32, 254,
			frActToTbl, 0, nlAttr(fraSrc, nlAddr("2001:db8::1"))))}, netutil.FamilyV4)
		assert.Error(t, err)
	})
	t.Run("encoded adds parse back", func(t *testing.T) {
		for _, want := range []Rule{ruleP1, ruleP2, ruleP3} {
			m := parseOneRequest(t, encodeRuleModify(1, want, true))
			m.typ = rtmNewRule
			got, err := rulesFromNetlink([]netlinkMessage{m}, netutil.FamilyV4)
			require.NoError(t, err)
			assert.Equal(t, []Rule{want}, got)
		}
	})
}

func TestRuleString(t *testing.T) {
	assert.Equal(t,
		"ipv4 pref 32765 from all fwmark 0x0/0xffffffff lookup 1397769217 proto 213",
		ruleP3.String())
	assert.Equal(t,
		"ipv4 pref 32763 from all lookup 254 suppress_prefixlength 0 proto 213",
		ruleP1.String())
	assert.Equal(t,
		"ipv6 pref 200 not from 2001:db8::/64 attrs [3] action 6 table 0",
		Rule{
			Family:     netutil.FamilyV6,
			Priority:   200,
			Invert:     true,
			Src:        netip.MustParsePrefix("2001:db8::/64"),
			Action:     6,
			OtherAttrs: []uint16{3},
		}.String())
}

func TestCheckRuleDelete(t *testing.T) {
	with := func(edit func(r *Rule)) Rule {
		r := ruleP3
		edit(&r)
		return r
	}

	tcs := []struct {
		name    string
		rule    Rule
		wantErr bool
	}{
		{name: "tagged rule", rule: ruleP3},
		{
			name:    "no preference",
			rule:    with(func(r *Rule) { r.Priority = 0 }),
			wantErr: true,
		},
		{name: "no table", rule: with(func(r *Rule) { r.Table = 0 }), wantErr: true},
		{name: "no action", rule: with(func(r *Rule) { r.Action = 0 }), wantErr: true},
		{
			name:    "no protocol attribute",
			rule:    with(func(r *Rule) { r.HasProtocol = false }),
			wantErr: true,
		},
		{name: "protocol 0", rule: with(func(r *Rule) { r.Protocol = 0 }), wantErr: true},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			err := checkRuleDelete(tc.rule)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestRuleDeleteAmbiguous(t *testing.T) {
	with := func(r Rule, edit func(r *Rule)) Rule {
		edit(&r)
		return r
	}
	markedP3 := with(ruleP3, func(r *Rule) { r.Fwmark, r.HasFwmark = 0x1, true })

	tcs := []struct {
		name   string
		target Rule
		dump   []Rule
		want   bool
	}{
		{name: "empty dump", target: ruleP3},
		{name: "only the target", target: ruleP3, dump: []Rule{ruleP1, ruleP2, ruleP3}},
		{
			name:   "a sent mark of 0 is the dumped rule",
			target: with(ruleP3, func(r *Rule) { r.HasFwmark = true }),
			dump:   []Rule{ruleP3},
		},
		{
			name:   "a zero mark matches a marked twin with the same mask",
			target: ruleP3,
			dump:   []Rule{markedP3, ruleP3},
			want:   true,
		},
		{
			name:   "a nonzero mark matches an unmarked twin",
			target: markedP3,
			dump:   []Rule{ruleP3, markedP3},
			want:   true,
		},
		{
			name:   "a twin with another mask matches",
			target: ruleP3,
			dump: []Rule{
				with(ruleP3, func(r *Rule) { r.Fwmask = 0xff }),
				ruleP3,
			},
			want: true,
		},
		{
			name:   "no source matches a twin with one",
			target: with(ruleP2, func(r *Rule) { r.Src = netip.Prefix{} }),
			dump: []Rule{
				ruleP2,
				with(ruleP2, func(r *Rule) { r.Src = netip.Prefix{} }),
			},
			want: true,
		},
		{
			name:   "a source matches a twin without one",
			target: ruleP2,
			dump:   []Rule{with(ruleP2, func(r *Rule) { r.Src = netip.Prefix{} }), ruleP2},
			want:   true,
		},
		{
			name:   "invert is not compared",
			target: ruleP3,
			dump:   []Rule{with(ruleP3, func(r *Rule) { r.Invert = true }), ruleP3},
			want:   true,
		},
		{
			name:   "selectors the delete does not send are not compared",
			target: ruleP3,
			dump: []Rule{
				with(ruleP3, func(r *Rule) { r.OtherAttrs = []uint16{3} }),
				ruleP3,
			},
			want: true,
		},
		{
			name:   "an absent suppress_prefixlength matches a twin with one",
			target: with(ruleP1, func(r *Rule) { r.HasSuppressPrefixlen = false }),
			dump:   []Rule{ruleP1},
			want:   true,
		},
		{
			name:   "a suppress_prefixlength matches a twin without one",
			target: ruleP1,
			dump: []Rule{
				with(ruleP1, func(r *Rule) { r.HasSuppressPrefixlen = false }),
				ruleP1,
			},
			want: true,
		},
		{
			name:   "a twin with another tag matches",
			target: ruleP3,
			dump:   []Rule{with(ruleP3, func(r *Rule) { r.Protocol = 4 }), ruleP3},
			want:   true,
		},
		{
			name:   "other tables, actions, preferences and families are left",
			target: ruleP3,
			dump: []Rule{
				with(ruleP3, func(r *Rule) { r.Action = 2 }),
				with(ruleP3, func(r *Rule) { r.Table = 254 }),
				with(ruleP3, func(r *Rule) { r.Family = netutil.FamilyV6 }),
				with(ruleP3, func(r *Rule) { r.Priority = 1 }),
				ruleP3,
			},
		},
		{
			name:   "target missing but another rule matches",
			target: ruleP3,
			dump:   []Rule{markedP3},
			want:   true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, RuleDeleteAmbiguous(tc.target, tc.dump))
		})
	}
}

func TestCheckRuleAdd(t *testing.T) {
	assert.NoError(t, checkRuleAdd(ruleP3))
	noPref := ruleP3
	noPref.Priority = 0
	assert.Error(t, checkRuleAdd(noPref))
}
