//go:build linux

package tun

import "github.com/rs/zerolog"

// CleanLeftovers removes the routes and rules that an earlier TUN mode run
// left behind when it ended without restoring them, such as on a crash. It
// runs at startup in every mode, before anything reads the routes, and
// never fails the start.
//
// It finds nothing yet, so nothing recovers from a crash: what such a run
// added stays until it is removed by hand or the host reboots.
func CleanLeftovers(logger zerolog.Logger) {
	// TODO(S4): find the capture rules tagged with protocol 213 and what is tied to
	// them.
}

// CheckLeftoversAfterReset warns about the routes and rules of this run
// that are still there after ResetJobs restored the network configuration,
// which points to a bug in a job's Reset. It removes nothing.
func CheckLeftoversAfterReset(logger zerolog.Logger) {
	// TODO(S4): look for what this run added.
}
