//go:build linux

package packet

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xvzc/spoofdpi/internal/inject"
	"github.com/xvzc/spoofdpi/internal/netutil"
)

func TestL2SenderError(t *testing.T) {
	route := &netutil.Route{Iface: net.Interface{Index: 2, Name: "eth0"}}

	for _, errno := range []syscall.Errno{syscall.EPERM, syscall.EACCES} {
		cause := fmt.Errorf("open pcap handle: failed to open raw socket: %w", errno)
		err := l2SenderError(route, cause)
		assert.ErrorIs(t, err, inject.ErrNeedsRoot)
		assert.ErrorIs(t, err, errno)
		assert.Equal(t, 1, strings.Count(err.Error(), "eth0"), err.Error())
	}

	timeout := errors.New("resolve gateway MAC: timed out")
	err := l2SenderError(route, timeout)
	assert.NotErrorIs(t, err, inject.ErrNeedsRoot)
	assert.Equal(t, "on eth0: resolve gateway MAC: timed out", err.Error())
}
