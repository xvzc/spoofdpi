//go:build !linux

package capture

import (
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/google/gopacket/pcap"
	"github.com/stretchr/testify/assert"
)

func TestIsReadTimeout(t *testing.T) {
	assert.True(t, IsReadTimeout(pcap.NextErrorTimeoutExpired))
	assert.True(t, IsReadTimeout(fmt.Errorf("read: %w", pcap.NextErrorTimeoutExpired)))
	assert.False(t, IsReadTimeout(pcap.NextErrorReadError))
	assert.False(t, IsReadTimeout(io.EOF))
	assert.False(t, IsReadTimeout(errors.New("timeout")))
	assert.False(t, IsReadTimeout(nil))
}
