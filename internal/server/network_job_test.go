package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	}, SurvivesReboot))

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
	}, SurvivesReboot))

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
	require.NoError(t, SaveJobs(state, []NetworkJob{failed, resetOnly}, SurvivesReboot))

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
	}, SurvivesReboot))

	require.Error(t, ApplyJobs(zerolog.Nop(), state))

	assert.False(t, fileExists(dir, "before"), "earlier job must be rolled back")
	assert.False(t, fileExists(dir, "after"), "later job must not be applied")
	assert.False(t, fileExists(dir, "required.reset"),
		"the rollback resets only the jobs before the failed one")
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
	require.NoError(t, SaveJobs(state, jobs, SurvivesReboot))

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

// setBootID makes id the current boot ID for the test.
func setBootID(t *testing.T, id string) {
	t.Helper()
	orig := currentBootID
	currentBootID = func() (string, error) { return id, nil }
	t.Cleanup(func() { currentBootID = orig })
}

// resetMarkerJob returns a job whose Reset creates the file name.reset in
// dir, so the file tells whether the reset ran.
func resetMarkerJob(dir, name string) NetworkJob {
	return NetworkJob{
		Description: name,
		Reset:       "touch " + executil.Quote(filepath.Join(dir, name+".reset")),
	}
}

// orderedJob returns a job like fileJob whose Reset also appends name to the
// file order in dir, so the file tells the order of the resets.
func orderedJob(dir, name string) NetworkJob {
	job := fileJob(dir, name, false)
	job.Reset = "sh -c " + executil.Quote(fmt.Sprintf(
		"rm %s && echo %s >> %s",
		executil.Quote(filepath.Join(dir, name)),
		name,
		executil.Quote(filepath.Join(dir, "order")),
	))
	return job
}

func TestResetJobs_BootIDs(t *testing.T) {
	tcs := []struct {
		name      string
		lifetime  Lifetime
		savedBoot string
		resetBoot string
		wantReset bool
	}{
		{"volatile from an earlier boot", ClearedByReboot, "boot-a", "boot-b", false},
		{"persistent from an earlier boot", SurvivesReboot, "boot-a", "boot-b", true},
		{"volatile from the same boot", ClearedByReboot, "boot-a", "boot-a", true},
		{"volatile without a saved boot ID", ClearedByReboot, "", "boot-b", true},
		{"volatile without a current boot ID", ClearedByReboot, "boot-a", "", true},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			state := filepath.Join(dir, "state")
			setBootID(t, tc.savedBoot)
			require.NoError(t, SaveJobs(
				state,
				[]NetworkJob{resetMarkerJob(dir, "job")},
				tc.lifetime,
			))

			setBootID(t, tc.resetBoot)
			var logs bytes.Buffer
			ResetJobs(zerolog.New(&logs), state)

			assert.Equal(t, tc.wantReset, fileExists(dir, "job.reset"))
			assert.False(t, fileExists(dir, "state"), "the state file must be deleted")
			assert.Equal(t, !tc.wantReset,
				strings.Contains(logs.String(), "discarded network state from a previous boot"))
		})
	}
}

func TestResetJobs_UnknownCurrentBootIDResets(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	setBootID(t, "boot-a")
	require.NoError(t, SaveJobs(
		state,
		[]NetworkJob{resetMarkerJob(dir, "job")},
		ClearedByReboot,
	))
	orig := currentBootID
	currentBootID = func() (string, error) { return "", errors.New("no boot id") }
	t.Cleanup(func() { currentBootID = orig })

	ResetJobs(zerolog.Nop(), state)

	assert.True(t, fileExists(dir, "job.reset"))
	assert.False(t, fileExists(dir, "state"))
}

func TestResetJobs_OldFormatResets(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	job := resetMarkerJob(dir, "job")
	old, err := json.Marshal(map[string]any{
		"jobs": []map[string]string{
			{"description": job.Description, "reset": job.Reset},
		},
		"createdAt": "2026-01-01T00:00:00Z",
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(state, old, 0o644))
	setBootID(t, "boot-b")

	ResetJobs(zerolog.Nop(), state)

	assert.True(t, fileExists(dir, "job.reset"))
	assert.False(t, fileExists(dir, "state"))
}

func TestResetJobs_LogsRestoreAndFailures(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	require.NoError(t, SaveJobs(state, []NetworkJob{
		{Description: "failing reset", Reset: "false"},
		resetMarkerJob(dir, "later"),
	}, SurvivesReboot))

	var logs bytes.Buffer
	ResetJobs(zerolog.New(&logs), state)

	out := logs.String()
	assert.True(t, fileExists(dir, "later.reset"))
	assert.Contains(
		t,
		out,
		`"level":"warn","error":"exit status 1","out":"","job":"failing reset","cmd":"false"`,
	)
	assert.Contains(t, out, "reset command failed (ignored)")
	assert.Contains(
		t,
		out,
		`{"level":"info","jobs":2,"state":"`+state+`","message":"restoring network configuration"}`,
	)
	assert.Contains(
		t,
		out,
		`{"level":"info","jobs":2,"state":"`+state+`","message":"network configuration restored"}`,
	)
	assert.Contains(t, out,
		`{"level":"debug","job":"later","message":"resetting network job"}`)
	assert.Less(
		t,
		strings.Index(out, `"job":"later"`),
		strings.Index(out, `"job":"failing reset"`),
		"jobs are reset in LIFO order",
	)
	assert.False(t, fileExists(dir, "state"),
		"the state file is deleted even when a reset fails")
}

func TestResetStaleJobs_LogsFoundState(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")

	var logs bytes.Buffer
	ResetStaleJobs(zerolog.New(&logs), state)
	assert.Empty(t, logs.String(), "no state file, nothing to log")

	require.NoError(t, SaveJobs(
		state,
		[]NetworkJob{resetMarkerJob(dir, "job")},
		SurvivesReboot,
	))
	ResetStaleJobs(zerolog.New(&logs), state)

	assert.Contains(t, logs.String(), "found network state from a previous run")
	assert.True(t, fileExists(dir, "job.reset"))
	assert.False(t, fileExists(dir, "state"))
}

// failStateWrites makes later saves fail after creating the temp file, as a
// full disk would.
func failStateWrites(t *testing.T) {
	t.Helper()
	failStateWritesAfter(t, 0)
}

// failStateWritesAfter is failStateWrites letting the next n saves succeed.
func failStateWritesAfter(t *testing.T, n int) {
	t.Helper()
	orig := createTempFile
	createTempFile = func(dir, pattern string) (*os.File, error) {
		f, err := orig(dir, pattern)
		if err != nil || n > 0 {
			n--
			return f, err
		}
		_ = f.Close()
		// A read-only file makes the write fail.
		return os.Open(f.Name())
	}
	t.Cleanup(func() { createTempFile = orig })
}

func TestSaveJobs_FailedWriteKeepsOldFile(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	oldJobs := []NetworkJob{{Description: "old", Reset: "r"}}
	require.NoError(t, SaveJobs(state, oldJobs, SurvivesReboot))
	failStateWrites(t)

	require.Error(t, SaveJobs(
		state,
		[]NetworkJob{{Description: "new", Reset: "r"}},
		SurvivesReboot,
	))

	got, ok, err := LoadJobs(state)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, oldJobs, got)
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Len(t, entries, 1, "the temp file must be removed")
}

func TestApplyJobs_SaveFailureRollsBackAppliedJobs(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	require.NoError(t, SaveJobs(state, []NetworkJob{
		orderedJob(dir, "first"),
		orderedJob(dir, "second"),
		failingJob(dir, "optional", true),
		fileJob(dir, "after", false),
	}, SurvivesReboot))
	failStateWrites(t)

	err := ApplyJobs(zerolog.Nop(), state)

	require.ErrorContains(t, err, "failed to save state")
	order, readErr := os.ReadFile(filepath.Join(dir, "order"))
	require.NoError(t, readErr)
	assert.Equal(t, "second\nfirst\n", string(order),
		"the applied jobs are reset in LIFO order")
	assert.False(t, fileExists(dir, "optional.reset"),
		"the failed optional job must not be reset")
	assert.False(t, fileExists(dir, "after"), "a later job must not be applied")
	assert.False(t, fileExists(dir, "state"), "the state file must be deleted")
}

func TestApplyJobs_RequiredFailureRollsBackResetOnlyJobs(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	require.NoError(t, SaveJobs(state, []NetworkJob{
		resetMarkerJob(dir, "reset-only"),
		fileJob(dir, "before", false),
		failingJob(dir, "required", false),
	}, SurvivesReboot))

	require.Error(t, ApplyJobs(zerolog.Nop(), state))

	assert.True(t, fileExists(dir, "reset-only.reset"),
		"a reset-only job before the failure is reset")
	assert.False(t, fileExists(dir, "before"))
	assert.False(t, fileExists(dir, "required.reset"))
	assert.False(t, fileExists(dir, "state"))
}

func TestApplyJobs_FirstJobFailureRollsBackNothing(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	require.NoError(t, SaveJobs(state, []NetworkJob{
		failingJob(dir, "required", false),
		fileJob(dir, "after", false),
	}, SurvivesReboot))

	var logs bytes.Buffer
	require.Error(t, ApplyJobs(zerolog.New(&logs), state))

	assert.False(t, fileExists(dir, "required.reset"))
	assert.False(t, fileExists(dir, "after"))
	assert.False(t, fileExists(dir, "state"))
	assert.NotContains(t, logs.String(), "restoring network configuration",
		"nothing to restore")
}

func TestApplyJobs_GroupSkipSaveFailureRollsBackAppliedJobs(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	failed := failingJob(dir, "failed", true)
	failed.Group = "g"
	skipped := resetMarkerJob(dir, "skipped")
	skipped.Group = "g"
	require.NoError(t, SaveJobs(state, []NetworkJob{
		orderedJob(dir, "first"),
		failed,
		skipped,
		fileJob(dir, "after", false),
	}, SurvivesReboot))
	// Dropping the failed job saves; dropping the skipped one fails.
	failStateWritesAfter(t, 1)

	err := ApplyJobs(zerolog.Nop(), state)

	require.ErrorContains(t, err, "failed to save state")
	order, readErr := os.ReadFile(filepath.Join(dir, "order"))
	require.NoError(t, readErr)
	assert.Equal(t, "first\n", string(order))
	assert.False(t, fileExists(dir, "failed.reset"))
	assert.False(t, fileExists(dir, "skipped.reset"),
		"a skipped job without Apply must not be reset")
	assert.False(t, fileExists(dir, "after"))
	assert.False(t, fileExists(dir, "state"))
}

func TestSaveJobs_FailedRenameRemovesTempFile(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	require.NoError(t, os.Mkdir(state, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(state, "child"), nil, 0o644))

	require.Error(t, SaveJobs(state, []NetworkJob{{Description: "job"}}, SurvivesReboot))

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1, "the temp file must be removed")
	assert.Equal(t, "state", entries[0].Name())
}

func TestSaveJobs_FileMode(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	require.NoError(
		t,
		SaveJobs(state, []NetworkJob{{Description: "job"}}, SurvivesReboot),
	)

	info, err := os.Stat(state)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), info.Mode().Perm())
}
