package trie

import (
	"encoding/binary"
	"fmt"
	"net"

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

// Set stores value for the given CIDR, overwriting any existing entry at that prefix.
func (t *CIDRTrie[T]) Add(cidr string, value T) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid cidr %q: %w", cidr, err)
	}

	ones, _ := ipNet.Mask.Size()
	idx := uint32(len(t.values))
	t.values = append(t.values, value)

	if ip4 := ipNet.IP.To4(); ip4 != nil {
		addr := patricia.NewIPv4Address(binary.BigEndian.Uint32(ip4), uint(ones))
		t.trie4.Set(addr, idx)
	} else {
		addr := patricia.NewIPv6Address(ipNet.IP, uint(ones))
		t.trie6.Set(addr, idx)
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
