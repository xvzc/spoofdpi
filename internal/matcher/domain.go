package matcher

import (
	"fmt"
	"strings"
	"sync"

	"github.com/xvzc/spoofdpi/internal/config"
)

// node represents a single node in the radix tree implementation.
type node struct {
	// children holds static sub-segments (e.g., "www", "api").
	children map[string]*node

	// wildcardChild holds the node for a '*' segment (matches one segment).
	wildcardChild *node

	// globstarChild holds the node for a '**' segment (matches all subsequent segments).
	globstarChild *node

	// rule stores the Rule pointer associated with the domain pattern terminating here.
	rule *config.Rule
}

// newNode creates a new Node, initializing its children map.
func newNode() *node {
	return &node{
		children: make(map[string]*node),
	}
}

// DomainMatcher is a radix tree for domain matching implementing the Matcher interface.
type DomainMatcher struct {
	mu   sync.RWMutex
	root *node
}

// NewDomainMatcher creates a new, empty domain matcher.
func NewDomainMatcher() *DomainMatcher {
	return &DomainMatcher{root: newNode()}
}

// reverseSegments reverses a slice of strings in place.
func reverseSegments(segments []string) {
	for i, j := 0, len(segments)-1; i < j; i, j = i+1, j-1 {
		segments[i], segments[j] = segments[j], segments[i]
	}
}

// splitAndReverseDomain splits a domain by '.' and reverses the segments.
func splitAndReverseDomain(domain string) []string {
	if domain == "" {
		return []string{}
	}
	// Remove trailing dot if present
	domain = strings.TrimSuffix(domain, ".")
	segments := strings.Split(domain, ".")
	reverseSegments(segments)
	return segments
}

// Add adds a rule to the tree based on its domain pattern.
func (t *DomainMatcher) Add(r *config.Rule) error {
	if r.Match == nil {
		return fmt.Errorf("domain rule must have match attribute")
	}

	if len(r.Match.Domains) == 0 {
		return fmt.Errorf("domain rule must have match.domain attribute")
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	for _, domain := range r.Match.Domains {
		segments := splitAndReverseDomain(domain)
		n := t.root

		for _, segment := range segments {
			switch segment {
			case "*":
				if n.wildcardChild == nil {
					n.wildcardChild = newNode()
				}
				n = n.wildcardChild
			case "**":
				if n.globstarChild == nil {
					n.globstarChild = newNode()
				}
				n = n.globstarChild
			default:
				if _, ok := n.children[segment]; !ok {
					n.children[segment] = newNode()
				}
				n = n.children[segment]
			}
		}

		// Resolve collisions by priority instead of refusing them outright.
		// Two rules covering the exact same domain are only ambiguous when
		// they share a priority — different priorities are deterministic
		// (the higher priority wins, the lower one is dropped).
		if existing := n.rule; existing != nil {
			if existing.Priority == r.Priority {
				return fmt.Errorf(
					"conflicting rules with the same priority %d for domain %q: %q and %q",
					r.Priority, domain, existing.Name, r.Name,
				)
			}
			if r.Priority < existing.Priority {
				continue // existing has higher priority — keep it
			}
			// new rule has higher priority — fall through to overwrite
		}

		n.rule = r
	}

	return nil
}

// Search searches for the highest priority rule matching the domain selector.
func (t *DomainMatcher) Search(s *Selector) *config.Rule {
	if s.Domain == nil {
		return nil
	}

	t.mu.RLock()
	defer t.mu.RUnlock()

	segments := splitAndReverseDomain(*s.Domain)
	matched := t.lookupRecursive(t.root, segments)
	if matched != nil {
		return matched.Clone()
	}

	return nil
}

// SearchAll finds the highest priority rule among multiple selectors.
func (t *DomainMatcher) SearchAll(ss []*Selector) *config.Rule {
	var bestRule *config.Rule

	for _, s := range ss {
		rule := t.Search(s)
		bestRule = GetHigherPriorityRule(bestRule, rule)
	}

	if bestRule != nil {
		return bestRule.Clone()
	}

	return nil
}

func (t *DomainMatcher) lookupRecursive(n *node, segments []string) *config.Rule {
	var bestMatch *config.Rule

	if len(segments) == 0 {
		bestMatch = GetHigherPriorityRule(bestMatch, n.rule)

		if n.wildcardChild != nil && n.wildcardChild.rule != nil {
			bestMatch = GetHigherPriorityRule(bestMatch, n.wildcardChild.rule)
		}

		if n.globstarChild != nil && n.globstarChild.rule != nil {
			bestMatch = GetHigherPriorityRule(bestMatch, n.globstarChild.rule)
		}

		return bestMatch
	}

	segment := segments[0]
	remainingSegments := segments[1:]

	// Priority Search: We must check ALL valid paths and pick the winner.

	// Path A: Static Child (Exact segment match)
	if child, ok := n.children[segment]; ok {
		match := t.lookupRecursive(child, remainingSegments)
		bestMatch = GetHigherPriorityRule(bestMatch, match)
	}

	// Path B: Wildcard Child ('*')
	if n.wildcardChild != nil {
		match := t.lookupRecursive(n.wildcardChild, remainingSegments)
		bestMatch = GetHigherPriorityRule(bestMatch, match)
	}

	// Path C: Globstar Child ('**')
	if n.globstarChild != nil {
		nGlobstar := n.globstarChild

		// 1. Terminal Globstar Match (e.g., pattern "**.google.com" matches "mail.google.com")
		// If the globstar node has a rule, it swallows all remaining segments.
		if nGlobstar.rule != nil {
			bestMatch = GetHigherPriorityRule(bestMatch, nGlobstar.rule)
		}

		// 2. Recursive Globstar Consumption
		// '**' node might have children (e.g., "foo.**.example.com").
		// We iterate through all possible split points of the remaining segments.
		// [FIXED] Changed loop to include len(segments) to handle consuming all segments
		for i := 0; i <= len(segments); i++ {
			match := t.lookupRecursive(nGlobstar, segments[i:])
			bestMatch = GetHigherPriorityRule(bestMatch, match)
		}
	}

	return bestMatch
}
