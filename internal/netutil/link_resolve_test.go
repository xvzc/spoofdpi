//go:build darwin || freebsd || linux

package netutil

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolveLinks(t *testing.T) {
	lookup := func(index int) (LinkInfo, error) {
		if index == 20 {
			return LinkInfo{}, fmt.Errorf("link %d: no such interface", index)
		}
		return LinkInfo{Index: index, Kind: LinkPhysical}, nil
	}

	got := resolveLinks([]int{4, 20, 5}, lookup)
	assert.Equal(t, []LinkInfo{
		{Index: 4, Kind: LinkPhysical},
		{Index: 5, Kind: LinkPhysical},
	}, got)

	none := resolveLinks([]int{20}, lookup)
	assert.Empty(t, none)
	assert.NotNil(t, none)

	failAll := func(int) (LinkInfo, error) { return LinkInfo{}, errors.New("boom") }
	assert.Empty(t, resolveLinks([]int{1, 2}, failAll))
}
