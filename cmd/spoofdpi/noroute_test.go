package main

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xvzc/spoofdpi/internal/netutil"
)

func TestNoIPv4RouteError(t *testing.T) {
	cause := fmt.Errorf("%w: discover gateway: no gateway found", netutil.ErrNoIPv4Route)

	err := noIPv4RouteError(cause, true)
	assert.ErrorIs(t, err, netutil.ErrNoIPv4Route)
	assert.ErrorContains(t, err, "need an IPv4 default route")
	assert.ErrorContains(t, err, "(IPv6 route: present)")
	assert.ErrorContains(t, err, "set --gateway")

	assert.ErrorContains(t, noIPv4RouteError(cause, false), "(IPv6 route: absent)")
}
