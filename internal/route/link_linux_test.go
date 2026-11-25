package route

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/netutil"
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

// TestDefaultLinks_Live dumps the real routing tables, which needs no
// privileges. The host may have no default route at all.
func TestDefaultLinks_Live(t *testing.T) {
	for _, fam := range []netutil.Family{netutil.FamilyV4, netutil.FamilyV6} {
		links, err := defaultLinks(fam)
		require.NoError(t, err, fam)
		for _, link := range links {
			t.Logf("%s default: %s", fam, describeLink(link))
			assert.Positive(t, link.Index)
			assert.NotEmpty(t, link.Name)
		}
	}
}
