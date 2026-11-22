package rule

import (
	"net"
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

	// Spellings of the same prefix are the same CIDR.
	spellings := [][2]string{
		{"10.0.0.0/8", "::ffff:10.0.0.0/104"},
		{"10.0.0.0/8", "10.0.0.1/8"},
	}
	for _, sp := range spellings {
		t.Run("cidr conflict "+sp[0]+" "+sp[1], func(t *testing.T) {
			rs := NewRuleSet()
			assert.NoError(t, rs.Add(mkRule("a", 10, nil, []string{sp[0]})))
			err := rs.Add(mkRule("b", 10, nil, []string{sp[1]}))
			if assert.Error(t, err) {
				assert.Contains(t, err.Error(), "conflict")
			}
		})

		for _, order := range [][2]string{{sp[0], sp[1]}, {sp[1], sp[0]}} {
			t.Run(
				"cidr higher priority wins "+order[0]+" then "+order[1],
				func(t *testing.T) {
					for _, highFirst := range []bool{true, false} {
						rs := NewRuleSet()
						high := mkRule("high", 20, nil, []string{order[0]})
						low := mkRule("low", 10, nil, []string{order[1]})
						first, second := low, high
						if highFirst {
							first, second = high, low
						}
						assert.NoError(t, rs.Add(first))
						assert.NoError(t, rs.Add(second))
						r := rs.Search([]Query{{MatchTypeAddr, "10.1.2.3"}})
						if assert.NotNil(t, r) {
							assert.Equal(t, "high", r.Name)
						}
					}
				},
			)
		}
	}

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

func TestRuleSet_MatchName(t *testing.T) {
	rs := NewRuleSet()
	assert.NoError(t, rs.Add(mkRule("domain", 10, []string{"example.com"}, nil)))
	assert.NoError(t, rs.Add(mkRule("cidr", 10, nil, []string{"192.0.2.0/24"})))

	tcs := []struct {
		name  string
		rs    *RuleSet
		value string
		want  string
	}{
		{"domain matches", rs, "example.com", "domain"},
		{"no domain matches", rs, "other.com", ""},
		{"empty name", rs, "", ""},
		{"nil rule set", nil, "example.com", ""},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.rs.MatchName(tc.value)
			if tc.want == "" {
				assert.Nil(t, r)
				return
			}
			if assert.NotNil(t, r) {
				assert.Equal(t, tc.want, r.Name)
			}
		})
	}
}

func TestRuleSet_MatchAddrs(t *testing.T) {
	rs := NewRuleSet()
	assert.NoError(t, rs.Add(mkRule("low", 10, nil, []string{"192.0.2.0/24"})))
	assert.NoError(t, rs.Add(mkRule("high", 20, nil, []string{"198.51.100.0/24"})))
	assert.NoError(t, rs.Add(mkRule("domain", 30, []string{"example.com"}, nil)))

	ips := func(ss ...string) []net.IP {
		out := make([]net.IP, len(ss))
		for i, s := range ss {
			out[i] = net.ParseIP(s)
		}
		return out
	}

	tcs := []struct {
		name  string
		rs    *RuleSet
		addrs []net.IP
		want  string
	}{
		{"address matches", rs, ips("192.0.2.1"), "low"},
		{"higher priority of all addresses", rs, ips("192.0.2.1", "198.51.100.1"), "high"},
		{"no address matches", rs, ips("203.0.113.1"), ""},
		{"no addresses", rs, nil, ""},
		{"nil rule set", nil, ips("192.0.2.1"), ""},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.rs.MatchAddrs(tc.addrs)
			if tc.want == "" {
				assert.Nil(t, r)
				return
			}
			if assert.NotNil(t, r) {
				assert.Equal(t, tc.want, r.Name)
			}
		})
	}
}
