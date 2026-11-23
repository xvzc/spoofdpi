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
