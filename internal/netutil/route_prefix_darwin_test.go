package netutil

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// TestPrefixFromReply_DarwinKernelForm reads netmasks in the compact form
// the darwin kernel writes them in, after a 92-byte rt_msghdr and with
// addresses rounded up to 4 bytes: cut after their last non-zero byte, and
// the default route's as a zero-length sockaddr.
func TestPrefixFromReply_DarwinKernelForm(t *testing.T) {
	addrs := unix.RTA_DST | unix.RTA_GATEWAY | unix.RTA_NETMASK

	t.Run("short netmask", func(t *testing.T) {
		body := []byte{
			// RTAX_DST: 10.0.0.0
			0x10, 0x02, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			// RTAX_GATEWAY: sockaddr_dl of index 20, 8 bytes
			0x08, 0x12, 20, 0, 0, 0, 0, 0,
			// RTAX_NETMASK: 255.0.0.0 in 5 bytes, padded to 8
			0x05, 0x00, 0, 0, 0xff, 0, 0, 0,
		}
		b := rtmKernelMessage(0x5c, unix.RTF_UP|unix.RTF_STATIC, 20, addrs, body)
		got, err := prefixFromBytes(t, b, "10.1.2.1")
		require.NoError(t, err)
		assert.Equal(t, netip.MustParsePrefix("10.0.0.0/8"), got)
	})

	t.Run("zero-length default netmask", func(t *testing.T) {
		body := []byte{
			// RTAX_DST: 0.0.0.0
			0x10, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			// RTAX_GATEWAY: 192.168.1.1
			0x10, 0x02, 0, 0, 192, 168, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0,
			// RTAX_NETMASK: zero-length sockaddr, padded to 4
			0x00, 0x00, 0, 0,
		}
		b := rtmKernelMessage(
			0x5c, unix.RTF_UP|unix.RTF_GATEWAY|unix.RTF_STATIC, 4, addrs, body,
		)
		got, err := prefixFromBytes(t, b, "192.0.2.1")
		require.NoError(t, err)
		assert.Equal(t, netip.MustParsePrefix("0.0.0.0/0"), got)
	})
}
