package route

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLinkKind_String(t *testing.T) {
	assert.Equal(t, "unknown", LinkUnknown.String())
	assert.Equal(t, "physical", LinkPhysical.String())
	assert.Equal(t, "ppp", LinkPPP.String())
	assert.Equal(t, "ip-tunnel", LinkIPTunnel.String())
	assert.Equal(t, "vpn", LinkVPN.String())
	assert.Equal(t, "loopback", LinkLoopback.String())
}
