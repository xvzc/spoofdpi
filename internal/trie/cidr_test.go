package trie

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCIDRTrie_Search(t *testing.T) {
	tr := NewCIDRTrie[string]()
	assert.NoError(t, tr.Add("192.168.1.0/24", "lan"))
	assert.NoError(t, tr.Add("10.0.0.0/8", "private"))
	assert.NoError(t, tr.Add("172.16.0.0/16", "wide"))
	assert.NoError(t, tr.Add("172.16.1.0/24", "narrow"))

	tcs := []struct {
		name  string
		ip    string
		want  string
		found bool
	}{
		{"match /24", "192.168.1.10", "lan", true},
		{"match /8", "10.0.0.5", "private", true},
		{"longer prefix wins: /24 over /16", "172.16.1.5", "narrow", true},
		{"match /16 only", "172.16.2.5", "wide", true},
		{"no match", "172.128.0.1", "", false},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			v, ok := tr.Search(tc.ip)
			assert.Equal(t, tc.found, ok)
			assert.Equal(t, tc.want, v)
		})
	}
}

func TestCIDRTrie_Set_InvalidCIDR(t *testing.T) {
	tr := NewCIDRTrie[string]()
	assert.Error(t, tr.Add("not-a-cidr", "v"))
}

func TestCIDRTrie_Search_InvalidIP(t *testing.T) {
	tr := NewCIDRTrie[string]()
	assert.NoError(t, tr.Add("192.168.0.0/24", "v"))
	_, ok := tr.Search("not-an-ip")
	assert.False(t, ok)
}

func TestCIDRTrie_Search_IPv6(t *testing.T) {
	tr := NewCIDRTrie[string]()
	assert.NoError(t, tr.Add("2001:db8::/32", "v6"))

	v, ok := tr.Search("2001:db8::1")
	assert.True(t, ok)
	assert.Equal(t, "v6", v)

	_, ok = tr.Search("2001:db9::1")
	assert.False(t, ok)
}
