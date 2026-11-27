package server

import (
	"fmt"
	"strings"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/executil"
)

// NetworkAction is one change to the network configuration, such as adding a
// route, or the change that undoes it.
type NetworkAction interface {
	// Run makes the change.
	Run() error
	// String describes the change for the logs.
	String() string
}

// CommandAction is a NetworkAction that runs a command, given as its argv,
// without a shell.
type CommandAction []string

// Run runs the command. Its error carries the command's output.
func (a CommandAction) Run() error {
	if len(a) == 0 {
		return fmt.Errorf("empty command")
	}
	out, err := executil.Run(a[0], a[1:]...)
	if err != nil {
		if out = strings.TrimSpace(out); out != "" {
			return fmt.Errorf("%w: %s", err, out)
		}
		return err
	}
	return nil
}

// String returns the argv joined by spaces. It is for display only: an
// argument with spaces in it reads as several.
func (a CommandAction) String() string {
	return strings.Join(a, " ")
}

// NetworkJob is a unit of network configuration, kept in memory only.
// Jobs are applied in order and reset in LIFO order.
type NetworkJob struct {
	Description string
	// Apply makes the change. A job without one has only a Reset, which
	// undoes something that comes into effect without a job, such as the
	// TUN interface.
	Apply NetworkAction
	// Reset undoes Apply. It may be nil.
	Reset NetworkAction
	// Optional marks a job whose failure is logged and skipped instead of
	// rolling back the jobs before it.
	Optional bool
	// Warning is logged at WARN level once Apply has succeeded.
	Warning string
	// Group ties jobs that only work together: once an optional job of a
	// group has failed, the later jobs of that group are skipped. Jobs
	// without a group are applied on their own.
	Group string
}

// ApplyJobs applies jobs in order and returns the ones applied, which
// ResetJobs resets at shutdown. When an optional job fails it logs the
// failure, leaves the job out and goes on with the next job; the later jobs
// of its Group are skipped and left out the same way. When a required job
// fails, it rolls back: it resets the jobs applied before it in LIFO order
// and returns the error. The failed job and the later ones are not reset, as
// they changed nothing, and their Reset could undo a matching configuration
// that they do not own.
func ApplyJobs(logger zerolog.Logger, jobs []NetworkJob) ([]NetworkJob, error) {
	var applied []NetworkJob
	failedGroups := make(map[string]bool)
	for _, job := range jobs {
		if job.Group != "" && failedGroups[job.Group] {
			logger.Warn().
				Str("job", job.Description).
				Str("group", job.Group).
				Msg("network job skipped: an earlier job of its group failed")
			continue
		}
		if job.Apply == nil {
			applied = append(applied, job)
			continue
		}
		logger.Debug().
			Str("job", job.Description).
			Stringer("action", job.Apply).
			Msg("applying network job")
		err := job.Apply.Run()
		if err == nil {
			if job.Warning != "" {
				logger.Warn().Msg(job.Warning)
			}
			applied = append(applied, job)
			continue
		}
		if !job.Optional {
			ResetJobs(logger, applied)
			return nil, fmt.Errorf("job %q: %s: %w", job.Description, job.Apply, err)
		}

		// The failed job changed nothing, so it must not be reset: its Reset
		// could undo a matching configuration that it does not own, such as
		// the existing route that made it fail.
		logger.Warn().Err(err).
			Str("job", job.Description).
			Stringer("action", job.Apply).
			Msg("optional network job failed; skipped")
		if job.Group != "" {
			failedGroups[job.Group] = true
		}
	}
	return applied, nil
}

// ResetJobs resets applied, the jobs ApplyJobs returned, in LIFO order,
// logging and ignoring failures.
func ResetJobs(logger zerolog.Logger, applied []NetworkJob) {
	if len(applied) == 0 {
		return
	}
	logger.Info().
		Int("jobs", len(applied)).
		Msg("restoring network configuration")
	for i := len(applied) - 1; i >= 0; i-- {
		job := applied[i]
		if job.Reset == nil {
			continue
		}
		logger.Debug().
			Str("job", job.Description).
			Stringer("action", job.Reset).
			Msg("resetting network job")
		if err := job.Reset.Run(); err != nil {
			logger.Warn().Err(err).
				Str("job", job.Description).
				Stringer("action", job.Reset).
				Msg("network job reset failed (ignored)")
		}
	}
	logger.Info().
		Int("jobs", len(applied)).
		Msg("network configuration restored")
}
