package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/logging"
)

func TestConnContext_NewTraceIDPerConnection(t *testing.T) {
	parentID := logging.NewTraceID()
	parent := logging.ContextWithTraceID(context.Background(), parentID)

	a, cancelA := ConnContext(parent)
	defer cancelA()
	b, cancelB := ConnContext(parent)
	defer cancelB()

	idA, ok := logging.TraceIDFromContext(a)
	require.True(t, ok)
	idB, ok := logging.TraceIDFromContext(b)
	require.True(t, ok)

	assert.NotEqual(t, parentID, idA, "a connection must not reuse the server's trace ID")
	assert.NotEqual(t, idA, idB, "each connection gets its own trace ID")
}

func TestConnContext_CancelledWithParent(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	ctx, cancel := ConnContext(parent)
	defer cancel()

	cancelParent()

	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("connection context not cancelled when the server context ended")
	}
}

func TestConnContext_CancelDoesNotAffectParent(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()

	ctx, cancel := ConnContext(parent)
	cancel()

	assert.Error(t, ctx.Err())
	assert.NoError(t, parent.Err())
}

func TestBackoff_Schedule(t *testing.T) {
	var b Backoff

	want := []time.Duration{
		5 * time.Millisecond,
		10 * time.Millisecond,
		20 * time.Millisecond,
		40 * time.Millisecond,
		80 * time.Millisecond,
		160 * time.Millisecond,
		320 * time.Millisecond,
		640 * time.Millisecond,
		time.Second,
		time.Second,
	}
	for i, w := range want {
		assert.Equal(t, w, b.next(), "delay %d", i)
	}
}

func TestBackoff_Reset(t *testing.T) {
	var b Backoff
	for range 5 {
		b.next()
	}

	b.Reset()

	assert.Equal(t, 5*time.Millisecond, b.next())
}

func TestBackoff_WaitSleeps(t *testing.T) {
	var b Backoff

	start := time.Now()
	b.Wait(context.Background())

	assert.GreaterOrEqual(t, time.Since(start), 5*time.Millisecond)
}

func TestBackoff_WaitReturnsWhenCancelled(t *testing.T) {
	b := Backoff{delay: time.Second} // the next Wait sleeps for the cap
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(10*time.Millisecond, cancel)

	start := time.Now()
	b.Wait(ctx)

	assert.Less(t, time.Since(start), 500*time.Millisecond)
}
