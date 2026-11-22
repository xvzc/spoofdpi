package trie

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/kentik/patricia"
	"github.com/kentik/patricia/uint32_tree"
)

// CIDRTrie matches IPs against CIDR prefixes using a patricia trie.
// Search returns the longest-prefix (most specific) match.
type CIDRTrie[T any] struct {
	values []T
	trie4  *uint32_tree.TreeV4
	trie6  *uint32_tree.TreeV6
}

func NewCIDRTrie[T any]() *CIDRTrie[T] {
	return &CIDRTrie[T]{
		trie4: uint32_tree.NewTreeV4(),
		trie6: uint32_tree.NewTreeV6(),
	}
}

// CanonicalCIDR parses cidr and returns the prefix it matches, masked. An
// IPv4-mapped IPv6 prefix, ::ffff:a.b.c.d/N, is the IPv4 prefix
// a.b.c.d/(N-96), as IPv4-mapped addresses are matched as IPv4; N must be
// at least 96. Two spellings of the same prefix, such as 10.0.0.1/8 and
// ::ffff:10.0.0.0/104, give the same result.
func CanonicalCIDR(cidr string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return netip.Prefix{}, err
	}

	if addr := prefix.Addr(); addr.Is4In6() {
		if prefix.Bits() < 96 {
			return netip.Prefix{}, errors.New(
				"an IPv4-mapped prefix must be at least /96",
			)
		}
		prefix = netip.PrefixFrom(addr.Unmap(), prefix.Bits()-96)
	}
	return prefix.Masked(), nil
}

// Set stores value for the given CIDR, overwriting any existing entry at that prefix.
// The prefix is the one CanonicalCIDR returns.
func (t *CIDRTrie[T]) Add(cidr string, value T) error {
	prefix, err := CanonicalCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid cidr %q: %w", cidr, err)
	}

	idx := uint32(len(t.values))
	t.values = append(t.values, value)

	bits := uint(prefix.Bits())
	if addr := prefix.Addr(); addr.Is4() {
		ip4 := addr.As4()
		t.trie4.Set(patricia.NewIPv4Address(binary.BigEndian.Uint32(ip4[:]), bits), idx)
	} else {
		ip16 := addr.As16()
		t.trie6.Set(patricia.NewIPv6Address(ip16[:], bits), idx)
	}
	return nil
}

// Search returns the value for the longest-prefix CIDR matching the given IP string.
func (t *CIDRTrie[T]) Search(key string) (T, bool) {
	ip := net.ParseIP(key)
	if ip == nil {
		var zero T
		return zero, false
	}
	if ip4 := ip.To4(); ip4 != nil {
		addr := patricia.NewIPv4AddressFromBytes(ip4, 32)
		if found, idx := t.trie4.FindDeepestTag(addr); found {
			return t.values[idx], true
		}
	} else if ip16 := ip.To16(); ip16 != nil {
		addr := patricia.NewIPv6Address(ip16, 128)
		if found, idx := t.trie6.FindDeepestTag(addr); found {
			return t.values[idx], true
		}
	}
	var zero T
	return zero, false
}
