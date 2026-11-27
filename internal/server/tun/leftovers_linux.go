//go:build linux

package tun

import (
	"sync"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/server"
)

// thisRun holds the table and rule prefs of this run's jobs once BuildJobs
// has chosen them, for CheckLeftoversAfterReset.
var thisRun struct {
	sync.Mutex
	run *captureRun
}

// recordThisRun keeps the table and rule prefs of info as this run's.
func recordThisRun(info *tunNetworkInfoLinux) {
	run := captureRun{
		table: info.CaptureTableID,
		prefs: map[netutil.Family][]uint32{
			netutil.FamilyV4: {info.MainRulePref, info.FromRulePref, info.CaptureRulePref},
		},
	}
	if info.IPv6MainRulePref != 0 {
		run.prefs[netutil.FamilyV6] = []uint32{
			info.IPv6MainRulePref,
			info.IPv6CaptureRulePref,
		}
	}
	thisRun.Lock()
	defer thisRun.Unlock()
	thisRun.run = &run
}

// CleanLeftovers removes the rules and routes that earlier TUN mode runs
// left behind when they ended without restoring them, such as on a crash.
// It runs at startup in every mode, before anything reads the routes, and
// never fails the start.
//
// A capture rule tagged with captureProtocol that looks up a capture table
// holding only TUN mode's routes is the anchor: it is removed with the
// tagged rules of its block and the tagged routes of its table. Everything
// else that looks like TUN mode's is only reported, with the command that
// removes it. While the TUN interface exists, another run is alive, and
// nothing is touched.
func CleanLeftovers(logger zerolog.Logger, _ CleanupOptions) {
	cleanCaptureLeftovers(logger, systemNetlink{})
}

// CheckLeftoversAfterReset warns about the rules and routes of this run
// that are still there after ResetJobs restored the network configuration,
// which points to a bug in a job's Reset. It removes nothing.
func CheckLeftoversAfterReset(logger zerolog.Logger) {
	thisRun.Lock()
	run := thisRun.run
	thisRun.Unlock()
	if run == nil {
		return
	}
	snap, err := takeCaptureSnapshot(systemNetlink{})
	if err != nil {
		logger.Warn().Err(err).Msg("failed to check for TUN mode rules and routes " +
			"left after restoring the network configuration")
		return
	}
	server.WarnLeftoversAfterReset(logger, leftoversAfterReset(snap, *run))
}
