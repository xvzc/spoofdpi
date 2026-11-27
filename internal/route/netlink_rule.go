package route

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/xvzc/spoofdpi/internal/netutil"
)

// Linux policy routing rule constants (<linux/rtnetlink.h>,
// <linux/fib_rules.h>); see netlink.go for why they are kept here.
const (
	rtmNewRule    = 32
	rtmDelRule    = 33
	rtmGetRule    = 34
	fibRuleHdrLen = 12

	fraSrc               = 2
	fraPriority          = 6
	fraFwmark            = 10
	fraSuppressPrefixlen = 14
	fraTable             = 15
	fraFwmask            = 16
	fraProtocol          = 21

	frActToTbl    = 1
	fibRuleInvert = 0x2

	// suppressPrefixlenUnset is the FRA_SUPPRESS_PREFIXLEN the kernel
	// dumps for a rule without suppress_prefixlength: -1 as a u32.
	suppressPrefixlenUnset = 0xffffffff
)

// RuleActionToTable is the action of a rule that looks up a table
// (FR_ACT_TO_TBL), the `lookup` of `ip rule`.
const RuleActionToTable uint8 = frActToTbl

// Rule is a Linux policy routing rule, as RTM_NEWRULE carries it. The Has
// fields report whether the attribute is there: a dump sets them from the
// kernel's reply, and AddRule and DeleteRule send only the attributes whose
// Has field is set. A delete is not exact: see RuleDeleteAmbiguous.
type Rule struct {
	Family netutil.Family
	// Priority is the rule's preference (FRA_PRIORITY). AddRule and
	// DeleteRule refuse 0 and always send it, so the kernel never picks
	// one.
	Priority uint32
	// Table is the table the rule looks up (FRA_TABLE), which may be above
	// 255.
	Table uint32
	// Action is the fib_rule_hdr action. AddRule sends RuleActionToTable
	// when it is zero.
	Action uint8
	// Invert reports the `not` of `ip rule` (FIB_RULE_INVERT). The
	// kernel's delete does not compare it.
	Invert bool
	// Src is the source prefix the rule selects (FRA_SRC and src_len), or
	// the zero Prefix for any source.
	Src netip.Prefix
	// TOS is the type of service the rule selects, or 0 for any.
	TOS uint8

	// Fwmark is the mark the rule selects (FRA_FWMARK). The kernel does
	// not dump a mark of 0, so a dumped rule for unmarked packets has
	// HasFwmark false and only the mask.
	Fwmark    uint32
	HasFwmark bool
	// Fwmask is the mask of Fwmark (FRA_FWMASK). Without it, the kernel
	// uses 0xffffffff for a nonzero mark and 0 for a zero mark, and a
	// mark and mask of 0 match every packet, so a rule for unmarked
	// packets has to send it.
	Fwmask    uint32
	HasFwmask bool

	SuppressPrefixlen    uint32
	HasSuppressPrefixlen bool

	// Protocol is the tag of the rule's origin (FRA_PROTOCOL). Kernels
	// before 4.17 neither keep nor dump it.
	Protocol    uint8
	HasProtocol bool

	// OtherAttrs are the types of the attributes of a dumped rule that the
	// fields above do not hold, such as FRA_DST, FRA_IIFNAME,
	// FRA_OIFNAME or FRA_UID_RANGE: selectors that make the rule
	// narrower. AddRule and DeleteRule do not send them.
	OtherAttrs []uint16
}

func (r Rule) String() string {
	s := fmt.Sprintf("%s pref %d", r.Family, r.Priority)
	if r.Invert {
		s += " not"
	}
	if r.Src.IsValid() {
		s += " from " + r.Src.String()
	} else {
		s += " from all"
	}
	if r.TOS != 0 {
		s += fmt.Sprintf(" tos %#x", r.TOS)
	}
	if r.HasFwmark || r.HasFwmask {
		s += fmt.Sprintf(" fwmark %#x", r.Fwmark)
		if r.HasFwmask {
			s += fmt.Sprintf("/%#x", r.Fwmask)
		}
	}
	if len(r.OtherAttrs) > 0 {
		s += fmt.Sprintf(" attrs %v", r.OtherAttrs)
	}
	if r.Action == frActToTbl || r.Action == 0 {
		s += fmt.Sprintf(" lookup %d", r.Table)
	} else {
		s += fmt.Sprintf(" action %d table %d", r.Action, r.Table)
	}
	if r.HasSuppressPrefixlen {
		s += fmt.Sprintf(" suppress_prefixlength %d", r.SuppressPrefixlen)
	}
	if r.HasProtocol {
		s += fmt.Sprintf(" proto %d", r.Protocol)
	}
	return s
}

// checkRuleAdd returns an error when r has no preference: the kernel
// would pick one, and a later delete could not name the rule.
func checkRuleAdd(r Rule) error {
	if r.Priority == 0 {
		return errors.New("no preference")
	}
	return nil
}

// checkRuleDelete returns an error when r is not a tagged rule of a chosen
// preference, table and action: the kernel takes a zero table, action or
// protocol as any, so such a delete could remove a rule that someone else
// added.
func checkRuleDelete(r Rule) error {
	switch {
	case r.Priority == 0:
		return errors.New("no preference")
	case r.Table == 0:
		return errors.New("no table")
	case r.Action == 0:
		return errors.New("no action")
	case !r.HasProtocol || r.Protocol == 0:
		return errors.New("no protocol tag")
	}
	return nil
}

// encodeRuleModify returns an RTM_NEWRULE (add) or RTM_DELRULE request for
// r. The table goes in FRA_TABLE, so that tables above 255 work. See
// RuleDeleteAmbiguous for the rules a delete may remove.
func encodeRuleModify(seq uint32, r Rule, add bool) []byte {
	u32 := func(v uint32) []byte { return binary.NativeEndian.AppendUint32(nil, v) }

	var attrs []byte
	attrs = appendAttr(attrs, fraPriority, u32(r.Priority))
	attrs = appendAttr(attrs, fraTable, u32(r.Table))
	var srcLen uint8
	if r.Src.IsValid() {
		srcLen = uint8(r.Src.Bits())
		attrs = appendAttr(attrs, fraSrc, r.Src.Addr().AsSlice())
	}
	if r.HasFwmark {
		attrs = appendAttr(attrs, fraFwmark, u32(r.Fwmark))
	}
	if r.HasFwmask {
		attrs = appendAttr(attrs, fraFwmask, u32(r.Fwmask))
	}
	if r.HasSuppressPrefixlen {
		attrs = appendAttr(attrs, fraSuppressPrefixlen, u32(r.SuppressPrefixlen))
	}
	if r.HasProtocol {
		attrs = appendAttr(attrs, fraProtocol, []byte{r.Protocol})
	}

	typ := uint16(rtmDelRule)
	action := r.Action
	if add {
		typ = rtmNewRule
		if action == 0 {
			action = frActToTbl
		}
	}
	var flags uint32
	if r.Invert {
		flags = fibRuleInvert
	}
	b := appendModifyHeader(nil, fibRuleHdrLen+len(attrs), typ, seq, add)
	b = append(b,
		linuxFamily(r.Family),
		0,      // dst_len
		srcLen, // src_len
		r.TOS,
		0,    // table: FRA_TABLE instead
		0, 0, // res1, res2
		action,
	)
	b = binary.NativeEndian.AppendUint32(b, flags)
	return append(b, attrs...)
}

// encodeRuleDump returns an RTM_GETRULE request that dumps the rules of
// fam.
func encodeRuleDump(seq uint32, fam netutil.Family) []byte {
	b := appendNetlinkHeader(nil, fibRuleHdrLen, rtmGetRule, nlmFRequest|nlmFDump, seq)
	b = append(b, linuxFamily(fam))
	return append(b, make([]byte, fibRuleHdrLen-1)...)
}

// parseNetlinkRule decodes data, the payload of an RTM_NEWRULE message of
// fam. FRA_TABLE, when present, overrides the 8-bit table of the header.
func parseNetlinkRule(data []byte, fam netutil.Family) (Rule, error) {
	if len(data) < fibRuleHdrLen {
		return Rule{}, errors.New("netlink: short rule message")
	}
	r := Rule{
		Family: fam,
		TOS:    data[3],
		Table:  uint32(data[4]),
		Action: data[7],
		Invert: binary.NativeEndian.Uint32(data[8:12])&fibRuleInvert != 0,
	}
	srcLen := int(data[2])
	u32 := func(val []byte) (uint32, bool) {
		if len(val) < 4 {
			return 0, false
		}
		return binary.NativeEndian.Uint32(val), true
	}
	var srcErr error
	err := walkAttrs(data[fibRuleHdrLen:], func(typ uint16, val []byte) {
		switch typ {
		case fraPriority:
			r.Priority, _ = u32(val)
		case fraTable:
			if v, ok := u32(val); ok {
				r.Table = v
			}
		case fraSrc:
			addr, ok := netip.AddrFromSlice(val)
			if !ok || familyOf(addr) != fam || srcLen > addr.BitLen() {
				srcErr = errors.New("netlink: rule with a bad source")
				return
			}
			r.Src = netip.PrefixFrom(addr, srcLen)
		case fraFwmark:
			r.Fwmark, r.HasFwmark = u32(val)
		case fraFwmask:
			r.Fwmask, r.HasFwmask = u32(val)
		case fraSuppressPrefixlen:
			v, ok := u32(val)
			if ok && v != suppressPrefixlenUnset {
				r.SuppressPrefixlen, r.HasSuppressPrefixlen = v, true
			}
		case fraProtocol:
			if len(val) >= 1 {
				r.Protocol, r.HasProtocol = val[0], true
			}
		default:
			r.OtherAttrs = append(r.OtherAttrs, typ)
		}
	})
	return r, errors.Join(err, srcErr)
}

// rulesFromNetlink reads the rules of fam from reply, the answer to
// encodeRuleDump.
func rulesFromNetlink(reply []netlinkMessage, fam netutil.Family) ([]Rule, error) {
	var rules []Rule
	for _, m := range reply {
		if m.typ != rtmNewRule || len(m.data) == 0 || m.data[0] != linuxFamily(fam) {
			continue
		}
		r, err := parseNetlinkRule(m.data, fam)
		if err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, nil
}

// RuleDeleteAmbiguous reports whether DeleteRule(target) could delete a
// rule of dump, a fresh Rules dump of target's family, other than target:
// when the delete filter may match more than one rule of dump, or one rule
// that is not target. Pass a rule of dump as target: a rule that only
// resembles one, such as one without the protocol that the kernel dumps,
// counts as another rule.
//
// It is strictly conservative, so that it holds on every kernel from 4.17
// on: any other rule of target's preference, table and action counts as a
// possible match, whatever its mark, mask, source, TOS, invert flag,
// suppress_prefixlength, protocol or other selectors. Kernels differ in
// which of these the delete compares; older ones may compare neither
// suppress_prefixlength nor the protocol.
func RuleDeleteAmbiguous(target Rule, dump []Rule) bool {
	var matches []Rule
	for _, r := range dump {
		if ruleDeleteMayMatch(target, r) {
			matches = append(matches, r)
		}
	}
	return len(matches) > 1 || len(matches) == 1 && !rulesEqual(matches[0], target)
}

// ruleDeleteMayMatch reports whether a delete of filter, as
// encodeRuleModify sends it, may remove r on some kernel (rule_find in
// net/core/fib_rules.c): r has filter's family and preference, and its
// table and action unless filter leaves them zero, which match any value.
// Every other attribute is taken as a possible wildcard.
func ruleDeleteMayMatch(filter, r Rule) bool {
	if r.Family != filter.Family || r.Priority != filter.Priority {
		return false
	}
	if filter.Action != 0 && r.Action != filter.Action {
		return false
	}
	return filter.Table == 0 || r.Table == filter.Table
}

// ruleMark returns the mark the kernel keeps for r.
func ruleMark(r Rule) uint32 {
	if r.HasFwmark {
		return r.Fwmark
	}
	return 0
}

// ruleMask returns the mask the kernel keeps for r: FRA_FWMASK, or else
// 0xffffffff for a nonzero mark.
func ruleMask(r Rule) uint32 {
	switch {
	case r.HasFwmask:
		return r.Fwmask
	case r.HasFwmark && r.Fwmark != 0:
		return 0xffffffff
	default:
		return 0
	}
}

// rulesEqual reports whether a and b are the same rule to the kernel: the
// same in every field, with the mark and mask the kernel keeps.
func rulesEqual(a, b Rule) bool {
	return a.Family == b.Family && a.Priority == b.Priority && a.Table == b.Table &&
		a.Action == b.Action && a.Invert == b.Invert && a.Src == b.Src &&
		a.TOS == b.TOS && ruleMark(a) == ruleMark(b) && ruleMask(a) == ruleMask(b) &&
		a.SuppressPrefixlen == b.SuppressPrefixlen &&
		a.HasSuppressPrefixlen == b.HasSuppressPrefixlen &&
		a.Protocol == b.Protocol && a.HasProtocol == b.HasProtocol &&
		slices.Equal(a.OtherAttrs, b.OtherAttrs)
}
