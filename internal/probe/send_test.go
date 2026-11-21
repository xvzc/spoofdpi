package probe

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/config"
)

// loopbackPair returns the two ends of a TCP connection on 127.0.0.1.
func loopbackPair(t *testing.T) (client *net.TCPConn, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	c, err := net.Dial("tcp4", ln.Addr().String())
	require.NoError(t, err)
	server = <-accepted
	require.NotNil(t, server)
	t.Cleanup(func() {
		_ = c.Close()
		_ = server.Close()
	})
	return c.(*net.TCPConn), server
}

func TestSendHello_ServerGetsTheClientHello(t *testing.T) {
	tcs := []struct {
		name string
		opts *config.HTTPSOptions
	}{
		{name: "unsplit", opts: unsplitOpts()},
		{name: "chunk 2", opts: chunkOpts(2)},
		{name: "chunk 35", opts: chunkOpts(35)},
		// On loopback a TTL of 1 still delivers, so the disordered chunks
		// arrive at once.
		{name: "disorder 5", opts: disorderOpts(5)},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			client, server := loopbackPair(t)
			msg, err := buildClientHello("www.example.com")
			require.NoError(t, err)

			require.NoError(
				t,
				sendHello(context.Background(), newHelloSender(), client, msg, tc.opts),
			)

			got := make([]byte, msg.Len())
			require.NoError(t, server.SetReadDeadline(time.Now().Add(5*time.Second)))
			_, err = io.ReadFull(server, got)
			require.NoError(t, err)
			assert.Equal(t, msg.Raw(), got)
			if tc.opts.Disorder {
				assert.Equal(t, 64, socketTTL(t, client), "the TTL is restored")
			}
		})
	}
}

func TestSendHello_DisorderNeedsTTL(t *testing.T) {
	msg, err := buildClientHello("www.example.com")
	require.NoError(t, err)
	err = sendHello(
		context.Background(),
		newHelloSender(),
		newFakeConn(),
		msg,
		disorderOpts(5),
	)
	assert.ErrorIs(t, err, errCannotSetTTL)
}

func TestChunkOpts(t *testing.T) {
	o := chunkOpts(20)
	assert.Equal(t, config.HTTPSSplitModeChunk, o.SplitMode)
	assert.Equal(t, uint8(20), o.ChunkSize)
	assert.False(t, o.Disorder)
	assert.False(t, o.UsesFakes())
	assert.True(t, disorderOpts(20).Disorder)
	assert.Equal(t, config.HTTPSSplitModeNone, unsplitOpts().SplitMode)
}
