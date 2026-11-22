package server

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/executil"
)

// NetworkJob is a serializable unit of network configuration.
// Jobs are applied in order and reset in LIFO order.
type NetworkJob struct {
	Description string `json:"description"`
	Apply       string `json:"apply,omitempty"`
	Reset       string `json:"reset,omitempty"`
	// Optional marks a job whose failure is logged and skipped instead of
	// rolling back the jobs before it.
	Optional bool `json:"optional,omitempty"`
	// Warning is logged at WARN level once Apply has succeeded.
	Warning string `json:"warning,omitempty"`
}

type jobState struct {
	Jobs      []NetworkJob `json:"jobs"`
	CreatedAt time.Time    `json:"createdAt"`
}

// SaveJobs marshals jobs to a JSON state file at path.
func SaveJobs(path string, jobs []NetworkJob) error {
	if path == "" {
		return nil
	}
	data, err := json.MarshalIndent(jobState{Jobs: jobs, CreatedAt: time.Now()}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// LoadJobs reads and unmarshals the state file at path.
// Returns (nil, false, nil) when path is empty or the file does not exist.
func LoadJobs(path string) ([]NetworkJob, bool, error) {
	if path == "" {
		return nil, false, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	var s jobState
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, false, err
	}
	return s.Jobs, true, nil
}

// ApplyJobs reads the state file at path and executes each Apply command in
// order. When a required job fails it calls ResetJobs to roll back before
// returning the error. When an optional job fails it logs the failure, drops
// the job from the state file and goes on with the next job.
// No-op when path is empty or the file does not exist.
func ApplyJobs(logger zerolog.Logger, path string) error {
	if path == "" {
		return nil
	}
	jobs, exists, err := LoadJobs(path)
	if err != nil {
		return fmt.Errorf("failed to load state: %w", err)
	}
	if !exists {
		return nil
	}
	for i := 0; i < len(jobs); i++ {
		job := jobs[i]
		if job.Apply == "" {
			continue
		}
		out, err := executil.Command(job.Apply)
		if err == nil {
			if job.Warning != "" {
				logger.Warn().Msg(job.Warning)
			}
			continue
		}
		if !job.Optional {
			ResetJobs(logger, path)
			return fmt.Errorf(
				"job %q: %s: %w",
				job.Description,
				strings.TrimSpace(out),
				err,
			)
		}

		logger.Warn().Err(err).
			Str("job", job.Description).
			Str("out", strings.TrimSpace(out)).
			Msg("optional network job failed; skipped")
		// The failed job changed nothing, so it must not be reset: its Reset
		// could undo a matching configuration that it does not own, such as
		// the existing route that made it fail.
		jobs = slices.Delete(jobs, i, i+1)
		i--
		if err := SaveJobs(path, jobs); err != nil {
			ResetJobs(logger, path)
			return fmt.Errorf("failed to save state: %w", err)
		}
	}
	return nil
}

// ResetJobs reads the state file at path and executes each Reset command in
// LIFO order, then deletes the file. No-op when path is empty or the file does
// not exist, so safe to call at startup for stale-state cleanup.
func ResetJobs(logger zerolog.Logger, path string) {
	if path == "" {
		return
	}
	jobs, exists, err := LoadJobs(path)
	if err != nil {
		logger.Warn().Err(err).Msg("failed to load network state")
		return
	}
	if !exists {
		return
	}
	for i := len(jobs) - 1; i >= 0; i-- {
		if cmd := jobs[i].Reset; cmd != "" {
			if out, err := executil.Command(cmd); err != nil {
				logger.Warn().Err(err).Str("out", strings.TrimSpace(out)).
					Str("cmd", cmd).Msg("reset command failed (ignored)")
			}
		}
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		logger.Warn().Err(err).Msg("failed to delete network state file")
	}
}
