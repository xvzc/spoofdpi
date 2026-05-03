package matcher

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xvzc/spoofdpi/internal/config"
)

func TestDomainMatcher(t *testing.T) {
	// Shared setup for table-driven tests
	matcher := NewDomainMatcher()

	rule1 := &config.Rule{
		Name:     "rule1",
		Priority: uint16(10),
		Match: &config.MatchAttrs{
			Domains: []string{"example.com"},
		},
	}

	rule2 := &config.Rule{
		Name:     "rule2",
		Priority: uint16(20),
		Match: &config.MatchAttrs{
			Domains: []string{"*.google.com"},
		},
	}

	rule3 := &config.Rule{
		Name:     "rule3",
		Priority: uint16(5),
		Match: &config.MatchAttrs{
			Domains: []string{"**.youtube.com"},
		},
	}

	// Additional rule for priority check
	rule4 := &config.Rule{
		Name:     "rule4",
		Priority: uint16(30),
		Match: &config.MatchAttrs{
			Domains: []string{"mail.google.com"},
		},
	}

	assert.NoError(t, matcher.Add(rule1))
	assert.NoError(t, matcher.Add(rule2))
	assert.NoError(t, matcher.Add(rule3))
	assert.NoError(t, matcher.Add(rule4))

	tcs := []struct {
		name     string
		selector *Selector
		assert   func(t *testing.T, output *config.Rule)
	}{
		{
			name:     "exact match",
			selector: &Selector{Domain: domainPtr("example.com")},
			assert: func(t *testing.T, output *config.Rule) {
				assert.NotNil(t, output)
				assert.Equal(t, "rule1", output.Name)
			},
		},
		{
			name:     "wildcard match",
			selector: &Selector{Domain: domainPtr("maps.google.com")},
			assert: func(t *testing.T, output *config.Rule) {
				assert.NotNil(t, output)
				assert.Equal(t, "rule2", output.Name)
			},
		},
		{
			name:     "globstar match",
			selector: &Selector{Domain: domainPtr("foo.bar.youtube.com")},
			assert: func(t *testing.T, output *config.Rule) {
				assert.NotNil(t, output)
				assert.Equal(t, "rule3", output.Name)
			},
		},
		{
			name:     "wildcard higher priority check",
			selector: &Selector{Domain: domainPtr("mail.google.com")},
			assert: func(t *testing.T, output *config.Rule) {
				// Should pick rule4 (priority 30) over rule2 (priority 20)
				assert.NotNil(t, output)
				assert.Equal(t, "rule4", output.Name)
			},
		},
		{
			name:     "no match",
			selector: &Selector{Domain: domainPtr("naver.com")},
			assert: func(t *testing.T, output *config.Rule) {
				assert.Nil(t, output)
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			output := matcher.Search(tc.selector)
			tc.assert(t, output)
		})
	}
}

func domainPtr(s string) *string { return &s }

// TestDomainMatcher_DuplicateDomainResolution pins the priority-based
// collision policy: two rules covering the exact same domain are
// only rejected when they share a priority. Different priorities are
// deterministic — the higher priority wins, the lower one is dropped.
func TestDomainMatcher_DuplicateDomainResolution(t *testing.T) {
	mkRule := func(name string, priority uint16) *config.Rule {
		return &config.Rule{
			Name:     name,
			Priority: priority,
			Match:    &config.MatchAttrs{Domains: []string{"dup.example.com"}},
		}
	}

	t.Run("higher-priority new rule overwrites existing", func(t *testing.T) {
		m := NewDomainMatcher()
		assert.NoError(t, m.Add(mkRule("low", 10)))
		assert.NoError(t, m.Add(mkRule("high", 20)))

		got := m.Search(&Selector{Domain: domainPtr("dup.example.com")})
		assert.NotNil(t, got)
		assert.Equal(t, "high", got.Name)
	})

	t.Run("lower-priority new rule is dropped silently", func(t *testing.T) {
		m := NewDomainMatcher()
		assert.NoError(t, m.Add(mkRule("high", 20)))
		assert.NoError(t, m.Add(mkRule("low", 10)))

		got := m.Search(&Selector{Domain: domainPtr("dup.example.com")})
		assert.NotNil(t, got)
		assert.Equal(t, "high", got.Name)
	})

	t.Run("equal priority returns error", func(t *testing.T) {
		m := NewDomainMatcher()
		assert.NoError(t, m.Add(mkRule("first", 10)))

		err := m.Add(mkRule("second", 10))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "same priority")
		assert.Contains(t, err.Error(), "dup.example.com")
		assert.Contains(t, err.Error(), `"first"`)
		assert.Contains(t, err.Error(), `"second"`)
	})
}
