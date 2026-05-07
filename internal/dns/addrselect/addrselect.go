package addrselect

import (
	"net"
	"net/netip"
	"sort"
)

// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Minimal RFC 6724 address selection.

func SortByRFC6724(addrs []netip.Addr) {
	if len(addrs) < 2 {
		return
	}
	sortByRFC6724withSrcs(addrs, srcAddrs(addrs))
}

func sortByRFC6724withSrcs(addrs []netip.Addr, srcs []netip.Addr) {
	if len(addrs) != len(srcs) {
		panic("internal error")
	}
	addrAttr := make([]ipAttr, len(addrs))
	srcAttr := make([]ipAttr, len(srcs))
	for i, v := range addrs {
		addrAttr[i] = ipAttrOf(v)
		srcAttr[i] = ipAttrOf(srcs[i])
	}
	sort.Stable(&byRFC6724{
		addrs:    addrs,
		addrAttr: addrAttr,
		srcs:     srcs,
		srcAttr:  srcAttr,
	})
}

// srcAddrs tries to UDP-connect to each address to see if it has a
// route. This does not send any packets. The destination port number
// is irrelevant.
func srcAddrs(addrs []netip.Addr) []netip.Addr {
	srcs := make([]netip.Addr, len(addrs))
	dst := net.UDPAddr{Port: 9}
	for i, addr := range addrs {
		dst.IP = addr.AsSlice()
		c, err := net.DialUDP("udp", nil, &dst)
		if err == nil {
			if src, ok := c.LocalAddr().(*net.UDPAddr); ok {
				srcs[i], _ = netip.AddrFromSlice(src.IP)
			}
			_ = c.Close()
		}
	}
	return srcs
}

type ipAttr struct {
	Scope      scope
	Precedence uint8
	Label      uint8
}

func ipAttrOf(ip netip.Addr) ipAttr {
	if !ip.IsValid() {
		return ipAttr{}
	}
	match := rfc6724policyTable.Classify(ip)
	return ipAttr{
		Scope:      classifyScope(ip),
		Precedence: match.Precedence,
		Label:      match.Label,
	}
}

type byRFC6724 struct {
	addrs    []netip.Addr
	addrAttr []ipAttr
	srcs     []netip.Addr
	srcAttr  []ipAttr
}

func (s *byRFC6724) Len() int { return len(s.addrs) }

func (s *byRFC6724) Swap(i, j int) {
	s.addrs[i], s.addrs[j] = s.addrs[j], s.addrs[i]
	s.srcs[i], s.srcs[j] = s.srcs[j], s.srcs[i]
	s.addrAttr[i], s.addrAttr[j] = s.addrAttr[j], s.addrAttr[i]
	s.srcAttr[i], s.srcAttr[j] = s.srcAttr[j], s.srcAttr[i]
}

// Less reports whether i is a better destination address for this
// host than j.
//
// The algorithm and variable names are from RFC 6724 section 6.
func (s *byRFC6724) Less(i, j int) bool {
	DA := s.addrs[i]
	DB := s.addrs[j]
	SourceDA := s.srcs[i]
	SourceDB := s.srcs[j]
	attrDA := &s.addrAttr[i]
	attrDB := &s.addrAttr[j]
	attrSourceDA := &s.srcAttr[i]
	attrSourceDB := &s.srcAttr[j]

	const preferDA = true
	const preferDB = false

	// Rule 1: Avoid unusable destinations.
	if !SourceDA.IsValid() && !SourceDB.IsValid() {
		return false
	}
	if !SourceDB.IsValid() {
		return preferDA
	}
	if !SourceDA.IsValid() {
		return preferDB
	}

	// Rule 2: Prefer matching scope.
	if attrDA.Scope == attrSourceDA.Scope && attrDB.Scope != attrSourceDB.Scope {
		return preferDA
	}
	if attrDA.Scope != attrSourceDA.Scope && attrDB.Scope == attrSourceDB.Scope {
		return preferDB
	}

	// Rule 3: Avoid deprecated addresses.
	// TODO(bradfitz): Implement this. Low priority for now.

	// Rule 4: Prefer home addresses.
	// TODO(bradfitz): Implement this. Low priority for now.

	// Rule 5: Prefer matching label.
	if attrSourceDA.Label == attrDA.Label &&
		attrSourceDB.Label != attrDB.Label {
		return preferDA
	}
	if attrSourceDA.Label != attrDA.Label &&
		attrSourceDB.Label == attrDB.Label {
		return preferDB
	}

	// Rule 6: Prefer higher precedence.
	if attrDA.Precedence > attrDB.Precedence {
		return preferDA
	}
	if attrDA.Precedence < attrDB.Precedence {
		return preferDB
	}

	// Rule 7: Prefer native transport.
	// TODO(bradfitz): Implement this. Low priority for now.

	// Rule 8: Prefer smaller scope.
	if attrDA.Scope < attrDB.Scope {
		return preferDA
	}
	if attrDA.Scope > attrDB.Scope {
		return preferDB
	}

	// Rule 9: Use the longest matching prefix.
	// Restricted to IPv6 to avoid issues with IPv4 (see issues 13283 and 18518).
	if !DA.Is4() && !DA.Is4In6() && !DB.Is4() && !DB.Is4In6() {
		commonA := commonPrefixLen(SourceDA, DA)
		commonB := commonPrefixLen(SourceDB, DB)

		if commonA > commonB {
			return preferDA
		}
		if commonA < commonB {
			return preferDB
		}
	}

	// Rule 10: Otherwise, leave the order unchanged.
	return false
}

type policyTableEntry struct {
	Prefix     netip.Prefix
	Precedence uint8
	Label      uint8
}

type policyTable []policyTableEntry

// RFC 6724 section 2.1.
// Items are sorted by the size of their Prefix.Mask.Size.
var rfc6724policyTable = policyTable{
	{
		// "::1/128"
		Prefix: netip.PrefixFrom(
			netip.AddrFrom16([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}),
			128,
		),
		Precedence: 50,
		Label:      0,
	},
	{
		// "::ffff:0:0/96"
		// IPv4-compatible, etc.
		Prefix: netip.PrefixFrom(
			netip.AddrFrom16([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff}),
			96,
		),
		Precedence: 35,
		Label:      4,
	},
	{
		// "::/96"
		Prefix:     netip.PrefixFrom(netip.AddrFrom16([16]byte{}), 96),
		Precedence: 1,
		Label:      3,
	},
	{
		// "2001::/32"
		// Teredo
		Prefix:     netip.PrefixFrom(netip.AddrFrom16([16]byte{0x20, 0x01}), 32),
		Precedence: 5,
		Label:      5,
	},
	{
		// "2002::/16"
		// 6to4
		Prefix:     netip.PrefixFrom(netip.AddrFrom16([16]byte{0x20, 0x02}), 16),
		Precedence: 30,
		Label:      2,
	},
	{
		// "3ffe::/16"
		Prefix:     netip.PrefixFrom(netip.AddrFrom16([16]byte{0x3f, 0xfe}), 16),
		Precedence: 1,
		Label:      12,
	},
	{
		// "fec0::/10"
		Prefix:     netip.PrefixFrom(netip.AddrFrom16([16]byte{0xfe, 0xc0}), 10),
		Precedence: 1,
		Label:      11,
	},
	{
		// "fc00::/7"
		Prefix:     netip.PrefixFrom(netip.AddrFrom16([16]byte{0xfc}), 7),
		Precedence: 3,
		Label:      13,
	},
	{
		// "::/0"
		Prefix:     netip.PrefixFrom(netip.AddrFrom16([16]byte{}), 0),
		Precedence: 40,
		Label:      1,
	},
}

// Classify returns the policyTableEntry of the entry with the longest
// matching prefix that contains ip.
// The table t must be sorted from largest mask size to smallest.
func (t policyTable) Classify(ip netip.Addr) policyTableEntry {
	if ip.Is4() {
		ip = netip.AddrFrom16(ip.As16())
	}
	for _, ent := range t {
		if ent.Prefix.Contains(ip) {
			return ent
		}
	}
	return policyTableEntry{}
}

// RFC 6724 section 3.1.
type scope uint8

const (
	scopeInterfaceLocal scope = 0x1
	scopeLinkLocal      scope = 0x2
	scopeAdminLocal     scope = 0x4
	scopeSiteLocal      scope = 0x5
	scopeOrgLocal       scope = 0x8
	scopeGlobal         scope = 0xe
)

func classifyScope(ip netip.Addr) scope {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return scopeLinkLocal
	}
	ipv6 := ip.Is6() && !ip.Is4In6()
	ipv6AsBytes := ip.As16()
	if ipv6 && ip.IsMulticast() {
		return scope(ipv6AsBytes[1] & 0xf)
	}
	if ipv6 && ipv6AsBytes[0] == 0xfe && ipv6AsBytes[1]&0xc0 == 0xc0 {
		return scopeSiteLocal
	}
	return scopeGlobal
}

// commonPrefixLen reports the length of the longest common prefix (in bits)
// between a and b, up to 64 bits for IPv6.
// Returns 0 if the addresses are different families.
func commonPrefixLen(a, b netip.Addr) (cpl int) {
	// Normalize 4-in-6 to plain IPv4 for consistent comparison.
	a = a.Unmap()
	b = b.Unmap()

	var aBytes, bBytes []byte
	if a.Is4() {
		if !b.Is4() {
			return 0
		}
		a4, b4 := a.As4(), b.As4()
		aBytes = a4[:]
		bBytes = b4[:]
	} else {
		if b.Is4() {
			return 0
		}
		a16, b16 := a.As16(), b.As16()
		// For IPv6, only up to the prefix (first 64 bits).
		aBytes = a16[:8]
		bBytes = b16[:8]
	}

	for i := range aBytes {
		if aBytes[i] == bBytes[i] {
			cpl += 8
			continue
		}
		ab, bb := aBytes[i], bBytes[i]
		bits := 8
		for {
			ab >>= 1
			bb >>= 1
			bits--
			if ab == bb {
				cpl += bits
				return
			}
		}
	}
	return
}
