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

func TestCIDRTrie_Add_IPv4Mapped(t *testing.T) {
	tr := NewCIDRTrie[string]()
	assert.NoError(t, tr.Add("::ffff:10.0.0.0/104", "mapped"))
	assert.NoError(t, tr.Add("::ffff:192.0.2.1/128", "host"))

	tcs := []struct {
		name  string
		ip    string
		want  string
		found bool
	}{
		{"ipv4 in prefix", "10.1.2.3", "mapped", true},
		{"ipv4-mapped in prefix", "::ffff:10.1.2.3", "mapped", true},
		{"ipv4 outside prefix", "11.0.0.1", "", false},
		{"ipv4 host", "192.0.2.1", "host", true},
		{"ipv4 next to host", "192.0.2.2", "", false},
		{"ipv6", "2001:db8::1", "", false},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			v, ok := tr.Search(tc.ip)
			assert.Equal(t, tc.found, ok)
			assert.Equal(t, tc.want, v)
		})
	}
}

func TestCIDRTrie_Add_IPv4MappedAll(t *testing.T) {
	tr := NewCIDRTrie[string]()
	assert.NoError(t, tr.Add("::ffff:0:0/96", "all ipv4"))

	v, ok := tr.Search("203.0.113.7")
	assert.True(t, ok)
	assert.Equal(t, "all ipv4", v)

	_, ok = tr.Search("2001:db8::1")
	assert.False(t, ok)
}

func TestCIDRTrie_Add_IPv4MappedTooShort(t *testing.T) {
	tr := NewCIDRTrie[string]()
	assert.Error(t, tr.Add("::ffff:0:0/64", "v"))

	_, ok := tr.Search("10.0.0.1")
	assert.False(t, ok)
	assert.Empty(t, tr.values, "a rejected cidr kept its value")
}

func TestCanonicalCIDR(t *testing.T) {
	tcs := []struct {
		cidr    string
		want    string
		wantErr bool
	}{
		{"10.0.0.0/8", "10.0.0.0/8", false},
		{"10.0.0.1/8", "10.0.0.0/8", false},
		{"::ffff:10.0.0.0/104", "10.0.0.0/8", false},
		{"::ffff:10.1.2.3/104", "10.0.0.0/8", false},
		{"::ffff:0:0/96", "0.0.0.0/0", false},
		{"2001:db8::1/32", "2001:db8::/32", false},
		{"::/64", "::/64", false},
		{"::ffff:0:0/64", "", true},
		{"not-a-cidr", "", true},
	}
	for _, tc := range tcs {
		t.Run(tc.cidr, func(t *testing.T) {
			got, err := CanonicalCIDR(tc.cidr)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.want, got.String())
		})
	}
}
