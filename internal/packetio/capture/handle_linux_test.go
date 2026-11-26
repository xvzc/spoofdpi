//go:build linux

package capture

import (
	"errors"
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestIsReadTimeout(t *testing.T) {
	assert.True(t, IsReadTimeout(unix.EAGAIN))
	assert.True(t, IsReadTimeout(unix.EWOULDBLOCK))
	assert.True(t, IsReadTimeout(fmt.Errorf("recvfrom: %w", unix.EAGAIN)))
	assert.False(t, IsReadTimeout(unix.EINTR))
	assert.False(t, IsReadTimeout(io.EOF))
	assert.False(t, IsReadTimeout(errors.New("timeout")))
	assert.False(t, IsReadTimeout(nil))
}

// AF_PACKET frames on lo carry a fake Ethernet header, though lo has no
// hardware address.
func TestLinuxHandleLinkType_Loopback(t *testing.T) {
	lo, err := net.InterfaceByName("lo")
	require.NoError(t, err)

	h := &LinuxHandle{fd: -1, ifIndex: lo.Index, buf: nil}
	assert.Equal(t, layers.LinkTypeEthernet, h.LinkType())
}
