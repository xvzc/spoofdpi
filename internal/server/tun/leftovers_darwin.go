//go:build darwin

package tun

import "github.com/rs/zerolog"

// CleanLeftovers removes the routes that an earlier TUN mode run left
// behind when it ended without restoring them, such as on a crash. It runs
// at startup in every mode, before anything reads the routes, and never
// fails the start.
//
// It finds nothing yet, so nothing recovers from a crash: what such a run
// added stays until it is removed by hand or the host reboots.
func CleanLeftovers(logger zerolog.Logger, opts CleanupOptions) {
	// TODO(S6): find the scoped default routes tagged with RTF_PROTO3.
}

// CheckLeftoversAfterReset warns about the routes of this run that are
// still there after ResetJobs restored the network configuration, which
// points to a bug in a job's Reset. It removes nothing.
func CheckLeftoversAfterReset(logger zerolog.Logger) {
	// TODO(S6): look for what this run added.
}
