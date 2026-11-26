package server

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/executil"
	"github.com/xvzc/spoofdpi/internal/sysinfo"
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
	// Group ties jobs that only work together: once an optional job of a
	// group has failed, the later jobs of that group are skipped. Jobs
	// without a group are applied on their own.
	Group string `json:"group,omitempty"`
}

// Lifetime tells whether the effects of a job set outlive a reboot.
type Lifetime int

const (
	// SurvivesReboot marks effects that stay after a reboot, such as system
	// proxy settings. Their state is always reset.
	SurvivesReboot Lifetime = iota
	// ClearedByReboot marks effects that a reboot clears, such as routes and
	// TUN devices. Their state is discarded unreset when it was saved in an
	// earlier boot, as its reset commands could hit configuration made since.
	ClearedByReboot
)

type jobState struct {
	Jobs      []NetworkJob `json:"jobs"`
	CreatedAt time.Time    `json:"createdAt"`
	// Volatile is set for ClearedByReboot jobs.
	Volatile bool `json:"volatile,omitempty"`
	// BootID identifies the boot the state was saved in. It is empty when
	// the OS has none or it could not be read.
	BootID string `json:"bootId,omitempty"`
}

// Seams for tests.
var (
	currentBootID  = sysinfo.BootID
	createTempFile = os.CreateTemp
)

// SaveJobs marshals jobs to a JSON state file at path, along with lifetime and
// the current boot ID. The file is replaced atomically, so a failed save
// leaves the previous state file intact.
func SaveJobs(path string, jobs []NetworkJob, lifetime Lifetime) error {
	if path == "" {
		return nil
	}
	bootID, _ := currentBootID()
	return saveState(path, jobState{
		Jobs:      jobs,
		CreatedAt: time.Now(),
		Volatile:  lifetime == ClearedByReboot,
		BootID:    bootID,
	})
}

func saveState(path string, s jobState) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := createTempFile(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Chmod(0o644)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// LoadJobs reads and unmarshals the state file at path.
// Returns (nil, false, nil) when path is empty or the file does not exist.
func LoadJobs(path string) ([]NetworkJob, bool, error) {
	s, exists, err := loadState(path)
	return s.Jobs, exists, err
}

func loadState(path string) (jobState, bool, error) {
	if path == "" {
		return jobState{}, false, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return jobState{}, false, nil
		}
		return jobState{}, false, err
	}
	var s jobState
	if err := json.Unmarshal(data, &s); err != nil {
		return jobState{}, false, err
	}
	return s, true, nil
}

// ApplyJobs reads the state file at path and executes each Apply command in
// order. When an optional job fails it logs the failure, drops the job from
// the state file and goes on with the next job; the later jobs of its Group
// are skipped and dropped the same way. When a required job fails, or the
// state file cannot be saved, it rolls back: it resets the jobs before the
// current one in LIFO order and deletes the state file. The current job and
// the later ones are not reset, as they changed nothing, and their Reset
// could undo a matching configuration that they do not own.
// No-op when path is empty or the file does not exist.
func ApplyJobs(logger zerolog.Logger, path string) error {
	if path == "" {
		return nil
	}
	state, exists, err := loadState(path)
	if err != nil {
		return fmt.Errorf("failed to load state: %w", err)
	}
	if !exists {
		return nil
	}
	jobs := state.Jobs
	// rollBack resets the jobs before i, which are the ones applied, and
	// deletes the state file.
	rollBack := func(i int) {
		resetJobList(logger, path, jobs[:i])
		removeStateFile(logger, path)
	}
	// dropJob removes the job at i, which changed nothing, from jobs and the
	// state file, rolling back on a save failure: the state file may still
	// list the dropped job.
	dropJob := func(i int) error {
		jobs = slices.Delete(jobs, i, i+1)
		state.Jobs = jobs
		if err := saveState(path, state); err != nil {
			rollBack(i)
			return fmt.Errorf("failed to save state: %w", err)
		}
		return nil
	}
	failedGroups := make(map[string]bool)
	for i := 0; i < len(jobs); i++ {
		job := jobs[i]
		if job.Group != "" && failedGroups[job.Group] {
			logger.Warn().
				Str("job", job.Description).
				Str("group", job.Group).
				Msg("network job skipped: an earlier job of its group failed")
			if err := dropJob(i); err != nil {
				return err
			}
			i--
			continue
		}
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
			rollBack(i)
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
		if job.Group != "" {
			failedGroups[job.Group] = true
		}
		// The failed job changed nothing, so it must not be reset: its Reset
		// could undo a matching configuration that it does not own, such as
		// the existing route that made it fail.
		if err := dropJob(i); err != nil {
			return err
		}
		i--
	}
	return nil
}

// ResetJobs reads the state file at path and executes each Reset command in
// LIFO order, then deletes the file. A state file of ClearedByReboot jobs
// saved in an earlier boot is deleted without running its Reset commands.
// No-op when path is empty or the file does not exist.
func ResetJobs(logger zerolog.Logger, path string) {
	resetStateFile(logger, path, false)
}

// ResetStaleJobs is ResetJobs for a state file left by an earlier run that did
// not restore its network configuration, such as one that crashed. It logs
// when it finds one.
func ResetStaleJobs(logger zerolog.Logger, path string) {
	resetStateFile(logger, path, true)
}

func resetStateFile(logger zerolog.Logger, path string, stale bool) {
	if path == "" {
		return
	}
	state, exists, err := loadState(path)
	if err != nil {
		logger.Warn().Err(err).Str("state", path).Msg("failed to load network state")
		return
	}
	if !exists {
		return
	}
	if stale {
		logger.Info().Str("state", path).Msg("found network state from a previous run")
	}
	if savedInEarlierBoot(state) {
		logger.Info().
			Int("jobs", len(state.Jobs)).
			Str("state", path).
			Msg("discarded network state from a previous boot")
	} else {
		resetJobList(logger, path, state.Jobs)
	}
	removeStateFile(logger, path)
}

// savedInEarlierBoot reports whether state is volatile and was saved in a boot
// other than the current one. It is false when either boot ID is unknown.
func savedInEarlierBoot(state jobState) bool {
	if !state.Volatile || state.BootID == "" {
		return false
	}
	current, err := currentBootID()
	return err == nil && current != "" && current != state.BootID
}

// resetJobList executes the Reset command of each job in LIFO order, logging
// and ignoring failures. path names the state file in the logs.
func resetJobList(logger zerolog.Logger, path string, jobs []NetworkJob) {
	if len(jobs) == 0 {
		return
	}
	logger.Info().
		Int("jobs", len(jobs)).
		Str("state", path).
		Msg("restoring network configuration")
	for i := len(jobs) - 1; i >= 0; i-- {
		cmd := jobs[i].Reset
		if cmd == "" {
			continue
		}
		logger.Debug().Str("job", jobs[i].Description).Msg("resetting network job")
		if out, err := executil.Command(cmd); err != nil {
			logger.Warn().Err(err).Str("out", strings.TrimSpace(out)).
				Str("job", jobs[i].Description).
				Str("cmd", cmd).Msg("reset command failed (ignored)")
		}
	}
	logger.Info().
		Int("jobs", len(jobs)).
		Str("state", path).
		Msg("network configuration restored")
}

func removeStateFile(logger zerolog.Logger, path string) {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		logger.Warn().Err(err).Str("state", path).
			Msg("failed to delete network state file")
	}
}
