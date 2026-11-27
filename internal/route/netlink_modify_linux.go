package route

import (
	"errors"
	"fmt"
	"slices"
	"syscall"

	"github.com/xvzc/spoofdpi/internal/netutil"
)

// The functions below change the kernel's addresses, links, routes and
// rules over netlink, which needs CAP_NET_ADMIN. A failure the kernel
// reports wraps its syscall.Errno, so that callers can test it with
// errors.Is: syscall.EEXIST for an add of an existing object, and for a
// missing one the errno that IsNotExist lists.

// IsNotExist reports whether err is the kernel's answer to a change of an
// object that does not exist: EADDRNOTAVAIL for an address, ENODEV for a
// link, ENOENT for a rule and ESRCH for a route.
func IsNotExist(err error) bool {
	return errors.Is(err, syscall.EADDRNOTAVAIL) || errors.Is(err, syscall.ENODEV) ||
		errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ESRCH)
}

// AddAddress adds a to its link, like `ip addr add`.
func AddAddress(a InterfaceAddr) error {
	if err := netlinkModify(func(seq uint32) []byte {
		return encodeAddrModify(seq, a, true)
	}); err != nil {
		return fmt.Errorf("add address %s: %w", a, err)
	}
	return nil
}

// DeleteAddress deletes a from its link, like `ip addr del`.
func DeleteAddress(a InterfaceAddr) error {
	if err := netlinkModify(func(seq uint32) []byte {
		return encodeAddrModify(seq, a, false)
	}); err != nil {
		return fmt.Errorf("delete address %s: %w", a, err)
	}
	return nil
}

// SetLinkUp sets the link with index up, like `ip link set up`.
func SetLinkUp(index int) error {
	if err := netlinkModify(func(seq uint32) []byte {
		return encodeLinkSetUp(seq, index, true)
	}); err != nil {
		return fmt.Errorf("set link %d up: %w", index, err)
	}
	return nil
}

// SetLinkDown sets the link with index down, like `ip link set down`.
func SetLinkDown(index int) error {
	if err := netlinkModify(func(seq uint32) []byte {
		return encodeLinkSetUp(seq, index, false)
	}); err != nil {
		return fmt.Errorf("set link %d down: %w", index, err)
	}
	return nil
}

// AddRoute adds r to its table, like `ip route add`.
func AddRoute(r RouteEntry) error {
	if err := checkRoute(r); err != nil {
		return fmt.Errorf("add route %s: %w", r, err)
	}
	if err := netlinkModify(func(seq uint32) []byte {
		return encodeRouteModify(seq, r, true)
	}); err != nil {
		return fmt.Errorf("add route %s: %w", r, err)
	}
	return nil
}

// DeleteRoute deletes the first route of r's table and destination that
// the kernel's filter matches, like `ip route del`. It refuses a route
// without a table or a protocol tag. The kernel compares only some fields
// of r, and of IPv6 routes neither the scope nor the type, so a delete can
// remove another route than r; RouteDeleteAmbiguous tells beforehand.
func DeleteRoute(r RouteEntry) error {
	if err := checkRouteDelete(r); err != nil {
		return fmt.Errorf("delete route %s: %w", r, err)
	}
	if err := netlinkModify(func(seq uint32) []byte {
		return encodeRouteModify(seq, r, false)
	}); err != nil {
		return fmt.Errorf("delete route %s: %w", r, err)
	}
	return nil
}

// Routes returns the routes of fam in every routing table. Callers pick
// a table by RouteEntry.Table.
func Routes(fam netutil.Family) ([]RouteEntry, error) {
	reply, err := netlinkDump(func(seq uint32) []byte {
		return encodeRouteDump(seq, fam)
	})
	if err != nil {
		return nil, fmt.Errorf("%s routes: %w", fam, err)
	}
	routes, err := routeEntriesFromNetlink(reply, fam)
	if err != nil {
		return nil, fmt.Errorf("%s routes: %w", fam, err)
	}
	return routes, nil
}

// AddRule adds r, like `ip rule add`. It refuses a rule without a
// preference.
func AddRule(r Rule) error {
	if err := checkRuleAdd(r); err != nil {
		return fmt.Errorf("add rule %s: %w", r, err)
	}
	if err := netlinkModify(func(seq uint32) []byte {
		return encodeRuleModify(seq, r, true)
	}); err != nil {
		return fmt.Errorf("add rule %s: %w", r, err)
	}
	return nil
}

// DeleteRule deletes the first rule of r's preference that the kernel's
// filter matches, like `ip rule del`. It refuses a rule without a
// preference, table, action or protocol tag. The kernel takes a zero mark,
// source length and TOS, an absent suppress_prefixlength, the invert flag
// and the selectors in OtherAttrs as wildcards, and older kernels may
// compare neither suppress_prefixlength nor the protocol, so a delete can
// remove another rule than r; RuleDeleteAmbiguous tells beforehand.
func DeleteRule(r Rule) error {
	if err := checkRuleDelete(r); err != nil {
		return fmt.Errorf("delete rule %s: %w", r, err)
	}
	if err := netlinkModify(func(seq uint32) []byte {
		return encodeRuleModify(seq, r, false)
	}); err != nil {
		return fmt.Errorf("delete rule %s: %w", r, err)
	}
	return nil
}

// Rules returns the policy routing rules of fam, in the kernel's order.
func Rules(fam netutil.Family) ([]Rule, error) {
	reply, err := netlinkDump(func(seq uint32) []byte {
		return encodeRuleDump(seq, fam)
	})
	if err != nil {
		return nil, fmt.Errorf("%s rules: %w", fam, err)
	}
	rules, err := rulesFromNetlink(reply, fam)
	if err != nil {
		return nil, fmt.Errorf("%s rules: %w", fam, err)
	}
	return rules, nil
}

// RuleProtocolSupported reports whether the kernel keeps the protocol tag
// of rules (FRA_PROTOCOL, Linux 4.17+): kernels that do dump it for every
// rule, so any IPv4 rule, such as the default ones, shows it. Older kernels
// drop the tag without an error. It reports false when there is no IPv4
// rule at all.
func RuleProtocolSupported() (bool, error) {
	rules, err := Rules(netutil.FamilyV4)
	if err != nil {
		return false, err
	}
	return slices.ContainsFunc(rules, func(r Rule) bool { return r.HasProtocol }), nil
}

// netlinkModify sends the request that encode returns for a new sequence
// number and waits for the kernel's acknowledgement.
func netlinkModify(encode func(seq uint32) []byte) error {
	seq := netlinkSeq.Add(1)
	_, err := netlinkRequest(encode(seq), seq, false)
	return err
}

// netlinkDump sends the dump request that encode returns for a new
// sequence number and returns every message of the dump. A dump that a
// concurrent change interrupts is tried once more.
func netlinkDump(encode func(seq uint32) []byte) ([]netlinkMessage, error) {
	var reply []netlinkMessage
	var err error
	for range 2 {
		seq := netlinkSeq.Add(1)
		reply, err = netlinkRequest(encode(seq), seq, true)
		if !errors.Is(err, errNetlinkDumpInterrupted) {
			break
		}
	}
	return reply, err
}
