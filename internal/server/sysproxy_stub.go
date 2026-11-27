//go:build !darwin

package server

import (
	"context"

	"github.com/rs/zerolog"
)

// SetupSystemProxy returns no jobs on platforms without system proxy support.
func SetupSystemProxy(
	_ context.Context,
	_ zerolog.Logger,
	_ string,
) ([]NetworkJob, error) {
	return nil, nil
}

// CleanSystemProxyLeftovers does nothing on platforms without system proxy
// support.
func CleanSystemProxyLeftovers(zerolog.Logger) {}

// CheckSystemProxyLeftoversAfterReset does nothing on platforms without
// system proxy support.
func CheckSystemProxyLeftoversAfterReset(zerolog.Logger) {}
