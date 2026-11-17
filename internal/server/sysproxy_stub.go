//go:build !darwin

package server

import "context"

// SetupSystemProxy is a no-op on platforms without system proxy support.
func SetupSystemProxy(_ context.Context, _ string, _ string) error {
	return nil
}
