package logging

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetGlobalLogger_AppLogsShareRunID(t *testing.T) {
	prevLogger, prevLevel := log.Logger, zerolog.GlobalLevel()
	t.Cleanup(func() {
		log.Logger = prevLogger
		zerolog.SetGlobalLevel(prevLevel)
	})

	runID := NewTraceID()
	connID := NewTraceID()
	runCtx := ContextWithTraceID(context.Background(), runID)
	var out bytes.Buffer
	SetGlobalLogger(runCtx, zerolog.TraceLevel, &out)

	appLogger := log.Logger.With().Ctx(runCtx).Logger()
	appLogger.Info().Msg("startup")
	appLogger.Info().Msg("resolver")
	log.Info().Msg("global")
	// A connection logs with its own context, even on the app's logger.
	connCtx := ContextWithTraceID(context.Background(), connID)
	connLogger := WithLocalScope(connCtx, appLogger, "conn")
	connLogger.Info().Msg("connected")

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	require.Len(t, lines, 4)
	assert.NotEqual(t, noTraceID, runID)
	for _, line := range lines[:3] {
		assert.Contains(t, line, runID)
	}
	assert.Contains(t, lines[3], connID)
	assert.NotContains(t, lines[3], runID)
	assert.NotContains(t, out.String(), noTraceID)
}
