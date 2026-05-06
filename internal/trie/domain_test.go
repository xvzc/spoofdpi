package trie

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDomainTrie_Search(t *testing.T) {
	tr := NewDomainTrie[string]()
	assert.NoError(t, tr.Add("example.com", "exact"))
	assert.NoError(t, tr.Add("*.google.com", "wildcard"))
	assert.NoError(t, tr.Add("**.youtube.com", "globstar"))
	assert.NoError(t, tr.Add("mail.google.com", "exact-over-wildcard"))

	tcs := []struct {
		name   string
		domain string
		want   string
		found  bool
	}{
		{"exact match", "example.com", "exact", true},
		{"wildcard match", "maps.google.com", "wildcard", true},
		{"wildcard matches apex", "google.com", "wildcard", true},
		{"exact beats wildcard", "mail.google.com", "exact-over-wildcard", true},
		{"globstar matches direct sub", "a.youtube.com", "globstar", true},
		{"globstar matches deep sub", "foo.bar.youtube.com", "globstar", true},
		{"globstar matches apex", "youtube.com", "globstar", true},
		{"wildcard does not match deep", "a.b.google.com", "", false},
		{"no match", "naver.com", "", false},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			v, ok := tr.Search(tc.domain)
			assert.Equal(t, tc.found, ok)
			assert.Equal(t, tc.want, v)
		})
	}
}

func TestDomainTrie_Set_Overwrite(t *testing.T) {
	tr := NewDomainTrie[string]()
	assert.NoError(t, tr.Add("example.com", "first"))
	assert.NoError(t, tr.Add("example.com", "second"))

	v, ok := tr.Search("example.com")
	assert.True(t, ok)
	assert.Equal(t, "second", v)
}

func TestDomainTrie_Set_EmptyPattern(t *testing.T) {
	tr := NewDomainTrie[string]()
	assert.Error(t, tr.Add("", "value"))
}

func TestDomainTrie_Search_TrailingDot(t *testing.T) {
	tr := NewDomainTrie[string]()
	assert.NoError(t, tr.Add("example.com", "v"))

	v, ok := tr.Search("example.com.")
	assert.True(t, ok)
	assert.Equal(t, "v", v)
}
