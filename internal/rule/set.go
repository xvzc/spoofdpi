package rule

import (
	"fmt"
	"sync"

	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/trie"
)

// RuleSet stores routing rules and resolves them by domain or CIDR.
//
// Domain rules use specificity-based matching (exact > * > **).
// CIDR rules use longest-prefix matching.
// Priority resolves conflicts at Add time and breaks ties when both
// a domain and a CIDR rule match the same request.
type RuleSet struct {
	mu         sync.RWMutex
	domain     *trie.DomainTrie[*config.Rule]
	cidr       *trie.CIDRTrie[*config.Rule]
	domainKeys map[string]*config.Rule
	cidrKeys   map[string]*config.Rule
}

func NewRuleSet() *RuleSet {
	return &RuleSet{
		domain:     trie.NewDomainTrie[*config.Rule](),
		cidr:       trie.NewCIDRTrie[*config.Rule](),
		domainKeys: make(map[string]*config.Rule),
		cidrKeys:   make(map[string]*config.Rule),
	}
}

func (rs *RuleSet) Add(r *config.Rule) error {
	if r.Match == nil {
		return fmt.Errorf("rule match attributes cannot be nil")
	}

	hasDomain := len(r.Match.Domains) > 0
	hasCIDR := len(r.Match.CIDRs) > 0

	if !hasDomain && !hasCIDR {
		return fmt.Errorf("invalid rule: match must contain 'domain' or 'cidrs'")
	}

	rs.mu.Lock()
	defer rs.mu.Unlock()

	for _, pattern := range r.Match.Domains {
		if existing, ok := rs.domainKeys[pattern]; ok {
			if existing.Priority == r.Priority {
				return fmt.Errorf(
					"rules '%s' and '%s' conflict on '%s' (priority %d)",
					existing.Name, r.Name, pattern, r.Priority,
				)
			}
			if r.Priority <= existing.Priority {
				continue
			}
		}
		if err := rs.domain.Add(pattern, r); err != nil {
			return err
		}
		rs.domainKeys[pattern] = r
	}

	for _, cidr := range r.Match.CIDRs {
		if existing, ok := rs.cidrKeys[cidr]; ok {
			if existing.Priority == r.Priority {
				return fmt.Errorf(
					"rules '%s' and '%s' conflict on '%s' (priority %d)",
					existing.Name, r.Name, cidr, r.Priority,
				)
			}
			if r.Priority <= existing.Priority {
				continue
			}
		}
		if err := rs.cidr.Add(cidr, r); err != nil {
			return err
		}
		rs.cidrKeys[cidr] = r
	}

	return nil
}

// Search returns the best matching rule for the given queries.
// When both a domain and a CIDR rule match, the higher-priority rule wins.
// The returned rule is a clone; nil is returned when nothing matches.
func (rs *RuleSet) Search(queries []Query) *config.Rule {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	var best *config.Rule
	for _, q := range queries {
		var r *config.Rule
		switch q.Type {
		case MatchTypeDomain:
			if v, ok := rs.domain.Search(q.Value); ok {
				r = v
			}
		case MatchTypeAddr:
			if v, ok := rs.cidr.Search(q.Value); ok {
				r = v
			}
		}
		best = HigherPriority(best, r)
	}

	if best == nil {
		return nil
	}
	return best.Clone()
}

// HigherPriority returns whichever rule has the higher Priority field.
// nil is treated as lower than any non-nil rule.
func HigherPriority(a, b *config.Rule) *config.Rule {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	if a.Priority >= b.Priority {
		return a
	}
	return b
}
