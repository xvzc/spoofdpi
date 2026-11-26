package server

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/executil"
)

// fileJob returns a job that creates the file name in dir when applied and
// removes it when reset, so the file tells whether the job is in effect.
func fileJob(dir, name string, optional bool) NetworkJob {
	path := executil.Quote(filepath.Join(dir, name))
	return NetworkJob{
		Description: name,
		Apply:       "touch " + path,
		Reset:       "rm " + path,
		Optional:    optional,
	}
}

// failingJob returns a job whose Apply fails and whose Reset creates the
// file name in dir, so the file tells whether the reset ran.
func failingJob(dir, name string, optional bool) NetworkJob {
	return NetworkJob{
		Description: name,
		Apply:       "false",
		Reset:       "touch " + executil.Quote(filepath.Join(dir, name+".reset")),
		Optional:    optional,
		Warning:     name + " applied",
	}
}

func fileExists(dir, name string) bool {
	_, err := os.Stat(filepath.Join(dir, name))
	return err == nil
}

func TestApplyJobs_OptionalFailureKeepsEarlierJobs(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	before := fileJob(dir, "before", false)
	before.Warning = "before applied"
	after := fileJob(dir, "after", false)
	require.NoError(t, SaveJobs(state, []NetworkJob{
		before,
		failingJob(dir, "optional", true),
		after,
	}))

	var logs bytes.Buffer
	require.NoError(t, ApplyJobs(zerolog.New(&logs), state))

	assert.True(t, fileExists(dir, "before"), "earlier job must stay applied")
	assert.True(t, fileExists(dir, "after"), "later job must still be applied")
	assert.Contains(t, logs.String(), "optional network job failed")
	assert.Contains(t, logs.String(), "before applied")
	assert.NotContains(t, logs.String(), "optional applied",
		"a failed job's warning must not be logged")

	jobs, ok, err := LoadJobs(state)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, []NetworkJob{before, after}, jobs,
		"the failed optional job must be dropped from the state")

	ResetJobs(zerolog.Nop(), state)
	assert.False(t, fileExists(dir, "before"))
	assert.False(t, fileExists(dir, "after"))
	assert.False(t, fileExists(dir, "optional.reset"),
		"a failed optional job must not be reset")
}

func TestApplyJobs_GroupFailureSkipsLaterGroupJobs(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	groupBefore := fileJob(dir, "group-before", true)
	groupBefore.Group = "g"
	failed := failingJob(dir, "group-failed", true)
	failed.Group = "g"
	groupAfter := fileJob(dir, "group-after", true)
	groupAfter.Group = "g"
	groupAfter.Warning = "group-after applied"
	other := fileJob(dir, "other", true)
	other.Group = "h"
	ungrouped := fileJob(dir, "ungrouped", false)
	require.NoError(t, SaveJobs(state, []NetworkJob{
		groupBefore,
		failed,
		groupAfter,
		other,
		ungrouped,
	}))

	var logs bytes.Buffer
	require.NoError(t, ApplyJobs(zerolog.New(&logs), state))

	assert.True(t, fileExists(dir, "group-before"),
		"a group job before the failure stays applied")
	assert.False(t, fileExists(dir, "group-after"),
		"a group job after the failure must be skipped")
	assert.True(t, fileExists(dir, "other"), "another group is not affected")
	assert.True(t, fileExists(dir, "ungrouped"), "a job without a group is applied")
	assert.Contains(t, logs.String(), "an earlier job of its group failed")
	assert.Contains(t, logs.String(), `"job":"group-after"`)
	assert.NotContains(t, logs.String(), "group-after applied",
		"a skipped job's warning must not be logged")

	jobs, ok, err := LoadJobs(state)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, []NetworkJob{groupBefore, other, ungrouped}, jobs,
		"the failed and the skipped jobs must be dropped from the state")

	ResetJobs(zerolog.Nop(), state)
	assert.False(t, fileExists(dir, "group-before"))
	assert.False(t, fileExists(dir, "other"))
	assert.False(t, fileExists(dir, "ungrouped"))
	assert.False(t, fileExists(dir, "group-failed.reset"))
}

func TestApplyJobs_GroupSkipsJobWithoutApply(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	failed := failingJob(dir, "failed", true)
	failed.Group = "g"
	resetOnly := NetworkJob{
		Description: "reset only",
		Reset:       "touch " + executil.Quote(filepath.Join(dir, "reset-only.reset")),
		Group:       "g",
	}
	require.NoError(t, SaveJobs(state, []NetworkJob{failed, resetOnly}))

	require.NoError(t, ApplyJobs(zerolog.Nop(), state))

	jobs, ok, err := LoadJobs(state)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Empty(t, jobs)
	ResetJobs(zerolog.Nop(), state)
	assert.False(t, fileExists(dir, "reset-only.reset"),
		"a skipped job must not be reset")
}

func TestApplyJobs_RequiredFailureRollsBack(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	require.NoError(t, SaveJobs(state, []NetworkJob{
		fileJob(dir, "before", false),
		failingJob(dir, "required", false),
		fileJob(dir, "after", false),
	}))

	require.Error(t, ApplyJobs(zerolog.Nop(), state))

	assert.False(t, fileExists(dir, "before"), "earlier job must be rolled back")
	assert.False(t, fileExists(dir, "after"), "later job must not be applied")
	assert.True(t, fileExists(dir, "required.reset"),
		"the rollback resets every job in the state")
	_, ok, err := LoadJobs(state)
	require.NoError(t, err)
	assert.False(t, ok, "the rollback must delete the state file")
}

func TestSaveJobs_RoundTrip(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	jobs := []NetworkJob{
		{Description: "required", Apply: "a", Reset: "r"},
		{Description: "optional", Apply: "a", Reset: "r", Optional: true, Warning: "w"},
		{Description: "grouped", Apply: "a", Reset: "r", Optional: true, Group: "g"},
	}
	require.NoError(t, SaveJobs(state, jobs))

	got, ok, err := LoadJobs(state)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, jobs, got)

	raw, err := os.ReadFile(state)
	require.NoError(t, err)
	assert.Equal(t, 2, bytes.Count(raw, []byte(`"optional": true`)),
		"a required job must not write the optional field")
	assert.Equal(t, 1, bytes.Count(raw, []byte(`"group"`)),
		"a job without a group must not write the group field")
}
