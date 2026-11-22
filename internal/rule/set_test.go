package rule

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xvzc/spoofdpi/internal/config"
)

func mkRule(
	name string, priority uint16, domains []string, cidrs []string,
) *config.Rule {
	return &config.Rule{
		Name:     name,
		Priority: priority,
		Match:    &config.MatchAttrs{Domains: domains, CIDRs: cidrs},
	}
}

// ┌──────────────┐
// │   RuleSet    │
// └──────────────┘

func TestRuleSet_Add(t *testing.T) {
	t.Run("nil match", func(t *testing.T) {
		rs := NewRuleSet()
		assert.Error(t, rs.Add(&config.Rule{Name: "bad"}))
	})

	t.Run("no domain or cidr", func(t *testing.T) {
		rs := NewRuleSet()
		assert.Error(t, rs.Add(&config.Rule{Name: "bad", Match: &config.MatchAttrs{}}))
	})

	t.Run("conflict same priority", func(t *testing.T) {
		rs := NewRuleSet()
		assert.NoError(t, rs.Add(mkRule("a", 10, []string{"dup.com"}, nil)))
		err := rs.Add(mkRule("b", 10, []string{"dup.com"}, nil))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "conflict")
	})

	t.Run("higher priority overwrites", func(t *testing.T) {
		rs := NewRuleSet()
		assert.NoError(t, rs.Add(mkRule("low", 10, []string{"dup.com"}, nil)))
		assert.NoError(t, rs.Add(mkRule("high", 20, []string{"dup.com"}, nil)))
		r := rs.Search([]Query{{MatchTypeDomain, "dup.com"}})
		assert.NotNil(t, r)
		assert.Equal(t, "high", r.Name)
	})

	t.Run("lower priority is dropped", func(t *testing.T) {
		rs := NewRuleSet()
		assert.NoError(t, rs.Add(mkRule("high", 20, []string{"dup.com"}, nil)))
		assert.NoError(t, rs.Add(mkRule("low", 10, []string{"dup.com"}, nil)))
		r := rs.Search([]Query{{MatchTypeDomain, "dup.com"}})
		assert.NotNil(t, r)
		assert.Equal(t, "high", r.Name)
	})
}

func TestRuleSet_Search_Domain(t *testing.T) {
	rs := NewRuleSet()
	assert.NoError(t, rs.Add(mkRule("exact", 10, []string{"example.com"}, nil)))
	assert.NoError(t, rs.Add(mkRule("wildcard", 20, []string{"*.google.com"}, nil)))
	assert.NoError(t, rs.Add(mkRule("glob", 5, []string{"**.youtube.com"}, nil)))
	assert.NoError(t, rs.Add(mkRule("mail", 30, []string{"mail.google.com"}, nil)))

	tcs := []struct {
		name   string
		domain string
		want   string
	}{
		{"exact match", "example.com", "exact"},
		{"wildcard match", "maps.google.com", "wildcard"},
		{"wildcard apex", "google.com", "wildcard"},
		{"exact beats wildcard", "mail.google.com", "mail"},
		{"globstar", "foo.bar.youtube.com", "glob"},
		{"no match returns nil", "naver.com", ""},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			r := rs.Search([]Query{{MatchTypeDomain, tc.domain}})
			if tc.want == "" {
				assert.Nil(t, r)
			} else {
				assert.NotNil(t, r)
				assert.Equal(t, tc.want, r.Name)
			}
		})
	}
}

func TestRuleSet_Search_CIDR(t *testing.T) {
	rs := NewRuleSet()
	assert.NoError(t, rs.Add(mkRule("wide", 5, nil, []string{"172.16.0.0/16"})))
	assert.NoError(t, rs.Add(mkRule("narrow", 4, nil, []string{"172.16.1.0/24"})))

	t.Run("longer prefix wins over higher priority", func(t *testing.T) {
		r := rs.Search([]Query{{MatchTypeAddr, "172.16.1.5"}})
		assert.NotNil(t, r)
		assert.Equal(t, "narrow", r.Name)
	})

	t.Run("falls back to wider prefix", func(t *testing.T) {
		r := rs.Search([]Query{{MatchTypeAddr, "172.16.2.5"}})
		assert.NotNil(t, r)
		assert.Equal(t, "wide", r.Name)
	})
}

func TestRuleSet_Search_DomainVsCIDR(t *testing.T) {
	rs := NewRuleSet()
	assert.NoError(t, rs.Add(mkRule("by-domain", 10, []string{"example.com"}, nil)))
	assert.NoError(t, rs.Add(mkRule("by-cidr", 20, nil, []string{"1.2.3.0/24"})))

	queries := []Query{
		{MatchTypeDomain, "example.com"},
		{MatchTypeAddr, "1.2.3.4"},
	}

	r := rs.Search(queries)
	assert.NotNil(t, r)
	assert.Equal(t, "by-cidr", r.Name)
}

func TestRuleSet_Search_ReturnsClone(t *testing.T) {
	rs := NewRuleSet()
	assert.NoError(t, rs.Add(mkRule("r", 10, []string{"example.com"}, nil)))

	r1 := rs.Search([]Query{{MatchTypeDomain, "example.com"}})
	r2 := rs.Search([]Query{{MatchTypeDomain, "example.com"}})
	assert.NotNil(t, r1)
	assert.NotSame(t, r1, r2)
}

// ┌──────────────────┐
// │  HigherPriority  │
// └──────────────────┘

func TestHigherPriority(t *testing.T) {
	r10 := &config.Rule{Priority: 10}
	r20 := &config.Rule{Priority: 20}

	tcs := []struct {
		name string
		a, b *config.Rule
		want *config.Rule
	}{
		{"a wins", r20, r10, r20},
		{"b wins", r10, r20, r20},
		{"equal prefers a", r10, r10, r10},
		{"nil a", nil, r10, r10},
		{"nil b", r10, nil, r10},
		{"both nil", nil, nil, nil},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, HigherPriority(tc.a, tc.b))
		})
	}
}
