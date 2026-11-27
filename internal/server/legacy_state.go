package server

import (
	"os"

	"github.com/rs/zerolog"
)

// legacyStateFiles are the paths where earlier versions of spoofdpi saved
// the commands that restore the network configuration.
var legacyStateFiles = []string{
	"/tmp/spoofdpi.darwin.tun.state",
	"/tmp/spoofdpi.linux.tun.state",
	"/tmp/spoofdpi.freebsd.tun.state",
	"/tmp/spoofdpi.http.darwin.state",
	"/tmp/spoofdpi.socks5.darwin.state",
}

// WarnLegacyStateFiles warns about each state file of an earlier version of
// spoofdpi that is still there. Anyone can create a file at these paths, so
// it only checks that the path exists: it never reads, follows, runs or
// removes the file.
func WarnLegacyStateFiles(logger zerolog.Logger) {
	warnLegacyStateFiles(logger, legacyStateFiles)
}

func warnLegacyStateFiles(logger zerolog.Logger, paths []string) {
	for _, path := range paths {
		if _, err := os.Lstat(path); err != nil {
			continue
		}
		logger.Warn().Msgf(
			"%q is a state file of an earlier version and no longer used by "+
				"spoofdpi; do not run the commands in it, delete it",
			path,
		)
	}
}
