//go:build !linux

package capture

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsReadTimeout(t *testing.T) {
	assert.True(t, IsReadTimeout(pcap.NextErrorTimeoutExpired))
	assert.True(t, IsReadTimeout(fmt.Errorf("read: %w", pcap.NextErrorTimeoutExpired)))
	assert.False(t, IsReadTimeout(pcap.NextErrorReadError))
	assert.False(t, IsReadTimeout(io.EOF))
	assert.False(t, IsReadTimeout(errors.New("timeout")))
	assert.False(t, IsReadTimeout(nil))
}

// openCaptureFile opens a pcap file with no packets, whose link type is
// the pcap file link type network.
func openCaptureFile(t *testing.T, network uint32) *DefaultHandle {
	t.Helper()

	// The global header: magic, version 2.4, time zone, accuracy, snap
	// length and link type.
	hdr := binary.LittleEndian.AppendUint32(nil, 0xa1b2c3d4)
	hdr = binary.LittleEndian.AppendUint16(hdr, 2)
	hdr = binary.LittleEndian.AppendUint16(hdr, 4)
	hdr = binary.LittleEndian.AppendUint32(hdr, 0)
	hdr = binary.LittleEndian.AppendUint32(hdr, 0)
	hdr = binary.LittleEndian.AppendUint32(hdr, 65535)
	hdr = binary.LittleEndian.AppendUint32(hdr, network)

	path := filepath.Join(t.TempDir(), "empty.pcap")
	require.NoError(t, os.WriteFile(path, hdr, 0o600))
	pcapHandle, err := pcap.OpenOffline(path)
	require.NoError(t, err)
	h := &DefaultHandle{pcapHandle}
	t.Cleanup(h.Close)
	return h
}

func TestDefaultHandle_LinkType(t *testing.T) {
	tcs := []struct {
		name    string
		network uint32
		want    layers.LinkType
	}{
		{"raw IP", 101, layers.LinkTypeRaw},
		{"PPP in HDLC framing", 50, layers.LinkTypePPP},
		{"Ethernet", 1, layers.LinkTypeEthernet},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, openCaptureFile(t, tc.network).LinkType())
		})
	}
}
