package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTraceID_Format(t *testing.T) {
	id := NewTraceID()

	assert.Regexp(t, `^[0-9a-f]{16}$`, id)
	assert.NotEqual(t, id, NewTraceID(), "each call returns a new trace ID")
}

func TestContextWithTraceID_ReplacesExisting(t *testing.T) {
	ctx := ContextWithTraceID(context.Background(), "aaaaaaaaaaaaaaaa")
	ctx = ContextWithTraceID(ctx, "bbbbbbbbbbbbbbbb")

	id, ok := TraceIDFromContext(ctx)
	require.True(t, ok)
	assert.Equal(t, "bbbbbbbbbbbbbbbb", id)
}

func TestTraceIDFromContext_Empty(t *testing.T) {
	id, ok := TraceIDFromContext(context.Background())

	assert.False(t, ok)
	assert.Equal(t, "0000000000000000", id)
}

// logWithHook logs one message through ctxHook and returns the JSON fields.
func logWithHook(t *testing.T, ctx context.Context) map[string]any {
	t.Helper()

	var buf bytes.Buffer
	logger := zerolog.New(&buf).Hook(ctxHook{}).With().Ctx(ctx).Logger()
	logger.Info().Msg("hello")

	fields := map[string]any{}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &fields))

	return fields
}

func TestCtxHook_TraceID(t *testing.T) {
	ctx := ContextWithTraceID(context.Background(), "0123456789abcdef")

	fields := logWithHook(t, ctx)

	assert.Equal(t, map[string]any{
		"level":          "info",
		traceIDFieldName: "0123456789abcdef",
		"message":        "hello",
	}, fields)
}

func TestCtxHook_ContextWithoutTraceID(t *testing.T) {
	fields := logWithHook(t, context.Background())

	assert.Equal(t, "0000000000000000", fields[traceIDFieldName])
}
