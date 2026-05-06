package trie

import (
	"fmt"
	"strings"
)

type domainNode[T any] struct {
	children      map[string]*domainNode[T]
	wildcardChild *domainNode[T]
	globstarChild *domainNode[T]
	value         T
	hasValue      bool
}

func newDomainNode[T any]() *domainNode[T] {
	return &domainNode[T]{children: make(map[string]*domainNode[T])}
}

// DomainTrie is a trie keyed by reversed domain segments.
// It supports exact, single-wildcard (*), and globstar (**) patterns.
// Search returns the most specific match: exact > * > **.
type DomainTrie[T any] struct {
	root *domainNode[T]
}

func NewDomainTrie[T any]() *DomainTrie[T] {
	return &DomainTrie[T]{root: newDomainNode[T]()}
}

// Set stores value at the given domain pattern, overwriting any existing value.
func (t *DomainTrie[T]) Add(pattern string, value T) error {
	segments, err := splitPattern(pattern)
	if err != nil {
		return err
	}

	n := t.root
	for _, seg := range segments {
		switch seg {
		case "*":
			if n.wildcardChild == nil {
				n.wildcardChild = newDomainNode[T]()
			}
			n = n.wildcardChild
		case "**":
			if n.globstarChild == nil {
				n.globstarChild = newDomainNode[T]()
			}
			n = n.globstarChild
		default:
			if n.children[seg] == nil {
				n.children[seg] = newDomainNode[T]()
			}
			n = n.children[seg]
		}
	}

	n.value = value
	n.hasValue = true
	return nil
}

// Search returns the value for the most specific pattern matching domain.
// Specificity order: exact > * > **.
// * and ** also match the apex domain (zero trailing segments).
func (t *DomainTrie[T]) Search(domain string) (T, bool) {
	segments := splitDomain(domain)
	return t.search(t.root, segments)
}

func (t *DomainTrie[T]) search(n *domainNode[T], segments []string) (T, bool) {
	if len(segments) == 0 {
		if n.hasValue {
			return n.value, true
		}
		if n.wildcardChild != nil && n.wildcardChild.hasValue {
			return n.wildcardChild.value, true
		}
		if n.globstarChild != nil && n.globstarChild.hasValue {
			return n.globstarChild.value, true
		}
		var zero T
		return zero, false
	}

	seg := segments[0]
	rest := segments[1:]

	// 1. Exact match (most specific).
	if child, ok := n.children[seg]; ok {
		if v, found := t.search(child, rest); found {
			return v, true
		}
	}

	// 2. Single wildcard (*).
	if n.wildcardChild != nil {
		if v, found := t.search(n.wildcardChild, rest); found {
			return v, true
		}
	}

	// 3. Globstar (**).
	if n.globstarChild != nil {
		ng := n.globstarChild
		if ng.hasValue {
			return ng.value, true
		}
		for i := 0; i <= len(segments); i++ {
			if v, found := t.search(ng, segments[i:]); found {
				return v, true
			}
		}
	}

	var zero T
	return zero, false
}

func splitPattern(pattern string) ([]string, error) {
	if pattern == "" {
		return nil, fmt.Errorf("empty domain pattern")
	}
	return splitDomain(pattern), nil
}

func splitDomain(domain string) []string {
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" {
		return nil
	}
	parts := strings.Split(domain, ".")
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return parts
}
