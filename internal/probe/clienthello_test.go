package probe

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/config"
)

func TestBuildClientHello(t *testing.T) {
	msg, err := buildClientHello("www.example.com")
	require.NoError(t, err)
	assert.True(t, msg.IsClientHello())

	raw := msg.Raw()
	start, end, err := msg.ExtractSNIOffset()
	require.NoError(t, err)
	assert.Equal(t, "www.example.com", string(raw[start:end]))
	assert.True(t, bytes.Contains(raw, []byte("\x02h2\x08http/1.1")), "ALPN is offered")
	// The X25519MLKEM768 key share alone is over a kilobyte.
	assert.Greater(t, len(raw), 1200)

	again, err := buildClientHello("www.example.com")
	require.NoError(t, err)
	assert.NotEqual(t, raw, again.Raw(), "each ClientHello has fresh random values")
}

func TestBuildClientHello_IPLiteralHasNoSNI(t *testing.T) {
	msg, err := buildClientHello("192.0.2.1")
	require.NoError(t, err)
	assert.True(t, msg.IsClientHello())
	_, _, err = msg.ExtractSNIOffset()
	assert.Error(t, err)
	assert.False(t, bytes.Contains(msg.Raw(), []byte("192.0.2.1")))
}

func TestSessionID(t *testing.T) {
	fake := []byte(config.FakeClientHello)
	assert.Equal(t, fake[44:76], sessionID(fake))

	msg, err := buildClientHello("www.example.com")
	require.NoError(t, err)
	assert.Len(t, sessionID(msg.Raw()), 32, "Go sends a session ID for TLS 1.3")
	assert.NotEqual(t, sessionID(fake), sessionID(msg.Raw()))

	assert.Nil(t, sessionID(fake[:43]), "too short for the length")
	assert.Nil(t, sessionID(fake[:50]), "too short for the session ID")
}
