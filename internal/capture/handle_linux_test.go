//go:build linux

package capture

import (
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
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
