package logging

import (
	"context"
	"math/rand/v2"
)

// traceIDCtxKey is unexported to prevent key collisions with other packages.
type traceIDCtxKey struct{}

// noTraceID is what TraceIDFromContext returns when ctx carries no trace ID,
// so log lines keep a fixed-width trace field.
const noTraceID = "0000000000000000"

// NewTraceID returns a new random trace ID of 16 lowercase hex characters.
func NewTraceID() string {
	b := make([]byte, 16)

	// A 64-bit random value is encoded as 16 hex characters.
	q := rand.Uint64()

	for i := 15; i >= 0; i-- {
		r := uint8(q & 0xF)
		q >>= 4
		if r > 9 {
			r += 0x27
		}
		b[i] = r + 0x30
	}

	return string(b)
}

// ContextWithTraceID returns a copy of ctx that carries id as its trace ID,
// replacing any trace ID ctx already carries.
func ContextWithTraceID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, traceIDCtxKey{}, id)
}

// TraceIDFromContext returns the trace ID ctx carries and true. When ctx
// carries none, it returns "0000000000000000" and false.
func TraceIDFromContext(ctx context.Context) (string, bool) {
	if id, ok := ctx.Value(traceIDCtxKey{}).(string); ok {
		return id, true
	}

	return noTraceID, false
}
