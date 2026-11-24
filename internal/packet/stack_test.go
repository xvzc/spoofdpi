package packet

import (
	"bytes"
	"errors"
	"net"
	"testing"

	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/capture"
)

// linkHandle is a filterHandle on the link type lt.
type linkHandle struct {
	*filterHandle
	lt layers.LinkType
}

func (h *linkHandle) LinkType() layers.LinkType { return h.lt }

// useCaptureHandle makes the stacks open h, or fail with openErr, for the
// rest of the test.
func useCaptureHandle(t *testing.T, h capture.Handle, openErr error) {
	t.Helper()

	orig := newCaptureHandle
	t.Cleanup(func() { newCaptureHandle = orig })
	newCaptureHandle = func(*net.Interface) (capture.Handle, error) {
		return h, openErr
	}
}

func TestOpenTCPStack(t *testing.T) {
	iface := &net.Interface{Name: "test0"}
	rejected := errors.New("program rejected")

	t.Run("a supported link type starts the sniffer", func(t *testing.T) {
		h := &linkHandle{&filterHandle{}, layers.LinkTypeEthernet}
		useCaptureHandle(t, h, nil)
		var logs bytes.Buffer

		stack, err := OpenTCPStack(
			zerolog.New(&logs), iface, Senders{}, NewHopStore(),
		)

		require.NoError(t, err)
		assert.NotNil(t, stack.Sniffer)
		assert.NotNil(t, stack.Seqs)
		assert.NotNil(t, stack.Writer)
		assert.NotEmpty(t, h.filter)
		assert.False(t, h.closed)
		assert.Empty(t, logs.String())
	})

	t.Run("an unsupported link type leaves nothing to learn", func(t *testing.T) {
		h := &linkHandle{&filterHandle{}, layers.LinkTypeLinuxSLL}
		useCaptureHandle(t, h, nil)
		var logs bytes.Buffer

		stack, err := OpenTCPStack(
			zerolog.New(&logs), iface, Senders{}, NewHopStore(),
		)

		require.NoError(t, err)
		assert.Nil(t, stack.Sniffer)
		assert.Nil(t, stack.Seqs)
		assert.NotNil(t, stack.Writer)
		assert.Empty(t, h.filter)
		assert.True(t, h.closed, "the handle is closed")
		assert.Zero(t, h.reads.Load())
		assert.Contains(t, logs.String(), `"level":"warn"`)
		assert.Contains(t, logs.String(), `"interface":"test0"`)
		assert.Contains(t, logs.String(), "unsupported link type: 113")
		assert.Contains(t, logs.String(),
			"hop counts and sequence numbers are not learned on this interface; "+
				"fake packets use hop-count-default and random sequence numbers")
	})

	t.Run("another sniffer error is fatal", func(t *testing.T) {
		h := &linkHandle{&filterHandle{setErr: rejected}, layers.LinkTypeEthernet}
		useCaptureHandle(t, h, nil)

		stack, err := OpenTCPStack(zerolog.Nop(), iface, Senders{}, NewHopStore())

		require.ErrorIs(t, err, rejected)
		assert.Nil(t, stack)
		assert.True(t, h.closed, "the handle is closed")
	})

	t.Run("an open error is fatal", func(t *testing.T) {
		useCaptureHandle(t, nil, rejected)

		stack, err := OpenTCPStack(zerolog.Nop(), iface, Senders{}, NewHopStore())

		require.ErrorIs(t, err, rejected)
		assert.Nil(t, stack)
	})
}

func TestOpenUDPStack(t *testing.T) {
	iface := &net.Interface{Name: "test0"}
	rejected := errors.New("program rejected")

	t.Run("a supported link type starts the sniffer", func(t *testing.T) {
		h := &linkHandle{&filterHandle{}, layers.LinkTypeEthernet}
		useCaptureHandle(t, h, nil)
		var logs bytes.Buffer

		stack, err := OpenUDPStack(
			zerolog.New(&logs), iface, Senders{}, NewHopStore(),
		)

		require.NoError(t, err)
		assert.NotNil(t, stack.Sniffer)
		assert.NotNil(t, stack.Writer)
		assert.NotEmpty(t, h.filter)
		assert.False(t, h.closed)
		assert.Empty(t, logs.String())
	})

	t.Run("an unsupported link type leaves nothing to learn", func(t *testing.T) {
		h := &linkHandle{&filterHandle{}, layers.LinkTypeLinuxSLL}
		useCaptureHandle(t, h, nil)
		var logs bytes.Buffer

		stack, err := OpenUDPStack(
			zerolog.New(&logs), iface, Senders{}, NewHopStore(),
		)

		require.NoError(t, err)
		assert.Nil(t, stack.Sniffer)
		assert.NotNil(t, stack.Writer)
		assert.Empty(t, h.filter)
		assert.True(t, h.closed, "the handle is closed")
		assert.Zero(t, h.reads.Load())
		assert.Contains(t, logs.String(), `"level":"warn"`)
		assert.Contains(t, logs.String(), `"interface":"test0"`)
		assert.Contains(t, logs.String(), "unsupported link type: 113")
		assert.Contains(t, logs.String(),
			"hop counts are not learned on this interface; "+
				"fake packets use hop-count-default")
	})

	t.Run("another sniffer error is fatal", func(t *testing.T) {
		h := &linkHandle{&filterHandle{setErr: rejected}, layers.LinkTypeEthernet}
		useCaptureHandle(t, h, nil)

		stack, err := OpenUDPStack(zerolog.Nop(), iface, Senders{}, NewHopStore())

		require.ErrorIs(t, err, rejected)
		assert.Nil(t, stack)
		assert.True(t, h.closed, "the handle is closed")
	})

	t.Run("an open error is fatal", func(t *testing.T) {
		useCaptureHandle(t, nil, rejected)

		stack, err := OpenUDPStack(zerolog.Nop(), iface, Senders{}, NewHopStore())

		require.ErrorIs(t, err, rejected)
		assert.Nil(t, stack)
	})
}
