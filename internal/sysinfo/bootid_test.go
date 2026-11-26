//go:build linux || darwin || freebsd

package sysinfo

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBootID_StableWithinBoot(t *testing.T) {
	first, err := BootID()
	if errors.Is(err, ErrBootIDUnsupported) {
		// A FreeBSD kernel without kern.boot_id has none; the state is then
		// always reset.
		t.Skip(err)
	}
	require.NoError(t, err)
	assert.NotEmpty(t, first)

	second, err := BootID()
	require.NoError(t, err)
	assert.Equal(t, first, second)
}
