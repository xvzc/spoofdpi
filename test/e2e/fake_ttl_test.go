//go:build e2e

package e2e

import (
	"reflect"
	"testing"
)

func TestLowTTLs_NonRoot(t *testing.T) {
	tcs := []struct {
		name string
		ttls []int
		want []int
	}{
		{"none", nil, nil},
		{"all above 1", []int{2, 7, 15}, nil},
		{"one", []int{1}, []int{1}},
		{"expired", []int{0, 5}, []int{0}},
		{"mixed", []int{9, 1, 2, 0}, []int{1, 0}},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if got := lowTTLs(tc.ttls); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("lowTTLs(%v) = %v, want %v", tc.ttls, got, tc.want)
			}
		})
	}
}
