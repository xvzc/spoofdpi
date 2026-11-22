package http

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPProxy_ServeStopsWithIdleConnection(t *testing.T) {
	var logs bytes.Buffer
	p := &HTTPProxy{
		logger:     zerolog.New(zerolog.SyncWriter(&logs)),
		listenAddr: net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, p.Listen(ctx))

	served := make(chan error, 1)
	go func() { served <- p.Serve(ctx) }()

	// The client sends nothing, so its handler waits in the request read.
	client, err := net.Dial("tcp", p.listener.Addr().String())
	require.NoError(t, err)
	defer func() { _ = client.Close() }()
	require.Eventually(t, func() bool { return p.conns.Active() == 1 },
		time.Second, 5*time.Millisecond)

	start := time.Now()
	cancel()

	select {
	case err := <-served:
		assert.NoError(t, err)
		assert.Less(t, time.Since(start), 2*time.Second)
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after ctx was cancelled")
	}

	require.NoError(t, client.SetReadDeadline(time.Now().Add(time.Second)))
	_, err = client.Read(make([]byte, 1))
	require.Error(t, err)
	var netErr net.Error
	if errors.As(err, &netErr) {
		assert.False(t, netErr.Timeout(), "the client must see the conn closed")
	}

	// Serve has returned, so every handler has finished logging.
	assert.Empty(t, logs.String(), "closing an idle conn at shutdown logs nothing")
}

func TestHTTPProxy_ListenAddressInUse(t *testing.T) {
	taken, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer func() { _ = taken.Close() }()

	p := &HTTPProxy{
		logger:     zerolog.Nop(),
		listenAddr: *taken.Addr().(*net.TCPAddr),
	}

	assert.Error(t, p.Listen(context.Background()))
}
