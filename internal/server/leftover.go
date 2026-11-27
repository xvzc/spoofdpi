package server

import "github.com/rs/zerolog"

// Leftover is network configuration that an earlier run of spoofdpi left
// behind, such as a rule of a run that crashed.
type Leftover struct {
	// Description tells what the leftover is, for the logs.
	Description string
	// Remove deletes the leftover. It is nil for a leftover that must not
	// be removed automatically, such as one that may belong to someone else.
	Remove func() error
	// ManualCommand removes the leftover by hand. The warnings about a
	// leftover that is not removed show it.
	ManualCommand string
}

// RemoveLeftovers removes leftovers, logging one INFO line for each one it
// removes, and one WARN line with the ManualCommand for each one it skips or
// fails to remove.
func RemoveLeftovers(logger zerolog.Logger, leftovers []Leftover) {
	for _, l := range leftovers {
		if l.Remove == nil {
			logger.Warn().
				Str("leftover", l.Description).
				Str("manual_command", l.ManualCommand).
				Msg("leftover network configuration not removed automatically")
			continue
		}
		if err := l.Remove(); err != nil {
			logger.Warn().Err(err).
				Str("leftover", l.Description).
				Str("manual_command", l.ManualCommand).
				Msg("failed to remove leftover network configuration")
			continue
		}
		logger.Info().
			Str("leftover", l.Description).
			Msg("removed leftover network configuration")
	}
}

// WarnLeftoversAfterReset logs one WARN line with the ManualCommand for each
// leftover that is still there after ResetJobs, and removes none of them.
func WarnLeftoversAfterReset(logger zerolog.Logger, leftovers []Leftover) {
	for _, l := range leftovers {
		logger.Warn().
			Str("leftover", l.Description).
			Str("manual_command", l.ManualCommand).
			Msg("network configuration left after restoring it")
	}
}
