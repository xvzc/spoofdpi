//go:build !darwin && !freebsd && !linux

package netutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLinkStub(t *testing.T) {
	link, err := linkInfo(3)
	require.NoError(t, err)
	assert.Equal(t, 3, link.Index)
	assert.Equal(t, LinkUnknown, link.Kind)

	links, err := defaultLinks(FamilyV4)
	require.NoError(t, err)
	assert.Empty(t, links)
}
