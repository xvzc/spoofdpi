package route

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLinkInfo_Loopback asks the real kernel over netlink, which needs no
// privileges.
func TestLinkInfo_Loopback(t *testing.T) {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skip("no lo interface")
	}

	link, err := linkInfo(lo.Index)
	require.NoError(t, err)
	assert.Equal(t, LinkInfo{
		Index: lo.Index, Name: "lo", Kind: LinkLoopback, Detail: "ARPHRD_LOOPBACK",
	}, link)

	_, err = linkInfo(1 << 30)
	assert.Error(t, err)
}
