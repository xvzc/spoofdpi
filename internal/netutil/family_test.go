package netutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFamily_String(t *testing.T) {
	assert.Equal(t, "ipv4", FamilyV4.String())
	assert.Equal(t, "ipv6", FamilyV6.String())
	assert.Equal(t, "unknown", Family(0).String())
}

func TestFamilySet_Has(t *testing.T) {
	tcs := []struct {
		name   string
		set    FamilySet
		v4, v6 bool
	}{
		{"empty", FamilySet(0), false, false},
		{"ipv4", NewFamilySet(FamilyV4), true, false},
		{"ipv6", NewFamilySet(FamilyV6), false, true},
		{"both", NewFamilySet(FamilyV6, FamilyV4), true, true},
		{"repeated", NewFamilySet(FamilyV4, FamilyV4), true, false},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.v4, tc.set.Has(FamilyV4))
			assert.Equal(t, tc.v6, tc.set.Has(FamilyV6))
			assert.False(t, tc.set.Has(Family(0)))
		})
	}
}
