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
