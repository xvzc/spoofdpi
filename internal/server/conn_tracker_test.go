package server

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConnTracker_CancelClosesConn(t *testing.T) {
	var tracker ConnTracker
	parent, cancelParent := context.WithCancel(context.Background())
	srvConn, client := net.Pipe()
	defer func() { _ = client.Close() }()

	readErr := make(chan error, 1)
	tracker.Go(parent, srvConn, func(_ context.Context) {
		// Blocks until the conn is closed; ignores ctx on purpose.
		_, err := srvConn.Read(make([]byte, 1))
		readErr <- err
	})

	cancelParent()

	select {
	case err := <-readErr:
		assert.ErrorIs(t, err, io.ErrClosedPipe)
	case <-time.After(time.Second):
		t.Fatal("cancelling the context did not close the connection")
	}
	assert.True(t, tracker.Wait(time.Second))
	assert.Zero(t, tracker.Active())
}

func TestConnTracker_WaitWhenDone(t *testing.T) {
	var tracker ConnTracker
	srvConn, client := net.Pipe()
	defer func() { _ = client.Close() }()

	ran := make(chan struct{})
	tracker.Go(context.Background(), srvConn, func(ctx context.Context) {
		close(ran)
	})

	assert.True(t, tracker.Wait(time.Second))
	select {
	case <-ran:
	default:
		t.Fatal("fn did not run")
	}
}

func TestConnTracker_WaitTimeout(t *testing.T) {
	var tracker ConnTracker
	srvConn, client := net.Pipe()
	defer func() { _ = client.Close() }()

	release := make(chan struct{})
	tracker.Go(context.Background(), srvConn, func(_ context.Context) {
		<-release
	})

	assert.False(t, tracker.Wait(50*time.Millisecond))
	assert.EqualValues(t, 1, tracker.Active())

	close(release)
	assert.True(t, tracker.Wait(time.Second))
}

func TestConnTracker_GoAfterWait(t *testing.T) {
	var tracker ConnTracker
	require.True(t, tracker.Wait(time.Second))

	srvConn, client := net.Pipe()
	defer func() { _ = client.Close() }()

	tracker.Go(context.Background(), srvConn, func(_ context.Context) {
		t.Error("fn must not run once Wait has started")
	})

	_, err := srvConn.Read(make([]byte, 1))
	assert.ErrorIs(t, err, io.ErrClosedPipe, "the conn is closed instead")
	assert.True(t, tracker.Wait(time.Second))
}
