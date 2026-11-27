package main

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xvzc/spoofdpi/internal/route"
)

func TestNoIPv4RouteError(t *testing.T) {
	cause := fmt.Errorf("discover egress: %w", route.ErrNoIPv4)

	err := noIPv4RouteError(cause, true)
	assert.ErrorIs(t, err, route.ErrNoIPv4)
	assert.ErrorContains(t, err, "need an IPv4 default route")
	assert.ErrorContains(t, err, "(IPv6 route: present)")
	assert.ErrorContains(t, err, "disable fake packets and use HTTP or SOCKS5 mode")

	assert.ErrorContains(t, noIPv4RouteError(cause, false), "(IPv6 route: absent)")
}

// TestNoIPv4RouteError_NoGatewayHint checks that the error no longer points
// at the removed --gateway option.
func TestNoIPv4RouteError_NoGatewayHint(t *testing.T) {
	cause := fmt.Errorf("discover egress: %w", route.ErrNoIPv4)
	for _, hasIPv6 := range []bool{true, false} {
		err := noIPv4RouteError(cause, hasIPv6)
		assert.NotContains(t, err.Error(), "gateway", "hasIPv6=%v", hasIPv6)
	}
}
