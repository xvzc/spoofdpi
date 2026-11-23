//go:build !darwin

package server

import (
	"context"

	"github.com/rs/zerolog"
)

// SetupSystemProxy is a no-op on platforms without system proxy support.
func SetupSystemProxy(_ context.Context, _ zerolog.Logger, _ string, _ string) error {
	return nil
}
