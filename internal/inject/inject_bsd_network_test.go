//go:build network && (darwin || freebsd)

package inject

import (
	"net"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/capture"
)

// openLiveCapture opens a capture on iface that passes what filter, a
// pcap filter expression, matches, and returns it with the link type its
// packets are decoded as.
func openLiveCapture(
	t *testing.T,
	iface *net.Interface,
	filter string,
) (capture.Handle, layers.LinkType) {
	t.Helper()
	h, err := capture.NewHandleWithReadTimeout(iface, 100*time.Millisecond)
	require.NoError(t, err)
	t.Cleanup(h.Close)
	dh, ok := h.(*capture.DefaultHandle)
	require.True(t, ok, "a pcap handle")
	require.NoError(t, dh.SetBPFFilter(filter))
	return h, h.LinkType()
}
