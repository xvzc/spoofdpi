package server

import (
	"bytes"
	"errors"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// actionLog records the actions that ran, in order.
type actionLog struct {
	ran []string
}

// fakeAction is a NetworkAction that records its name in log when it runs
// and returns err.
type fakeAction struct {
	name string
	log  *actionLog
	err  error
}

func (a fakeAction) Run() error {
	a.log.ran = append(a.log.ran, a.name)
	return a.err
}

func (a fakeAction) String() string { return a.name }

// job returns a job whose Apply and Reset record "apply <name>" and
// "reset <name>" in log.
func (l *actionLog) job(name string, optional bool) NetworkJob {
	return NetworkJob{
		Description: name,
		Apply:       fakeAction{name: "apply " + name, log: l},
		Reset:       fakeAction{name: "reset " + name, log: l},
		Optional:    optional,
	}
}

// failingJob is job with an Apply that fails.
func (l *actionLog) failingJob(name string, optional bool) NetworkJob {
	j := l.job(name, optional)
	j.Apply = fakeAction{name: "apply " + name, log: l, err: errors.New("failed")}
	j.Warning = name + " applied"
	return j
}

func descriptions(jobs []NetworkJob) []string {
	var out []string
	for _, j := range jobs {
		out = append(out, j.Description)
	}
	return out
}

func TestApplyJobs_OptionalFailureKeepsEarlierJobs(t *testing.T) {
	var l actionLog
	before := l.job("before", false)
	before.Warning = "before applied"
	jobs := []NetworkJob{before, l.failingJob("optional", true), l.job("after", false)}

	var logs bytes.Buffer
	applied, err := ApplyJobs(zerolog.New(&logs), jobs)
	require.NoError(t, err)

	assert.Equal(t, []string{"apply before", "apply optional", "apply after"}, l.ran)
	assert.Equal(t, []string{"before", "after"}, descriptions(applied),
		"the failed optional job must be left out")
	assert.Contains(t, logs.String(), "optional network job failed")
	assert.Contains(t, logs.String(), `"action":"apply optional"`)
	assert.Contains(t, logs.String(), "before applied")
	assert.NotContains(t, logs.String(), "optional applied",
		"a failed job's warning must not be logged")

	l.ran = nil
	ResetJobs(zerolog.Nop(), applied)
	assert.Equal(t, []string{"reset after", "reset before"}, l.ran,
		"a failed optional job must not be reset")
}

func TestApplyJobs_GroupFailureSkipsLaterGroupJobs(t *testing.T) {
	var l actionLog
	groupBefore := l.job("group-before", true)
	groupBefore.Group = "g"
	failed := l.failingJob("group-failed", true)
	failed.Group = "g"
	groupAfter := l.job("group-after", true)
	groupAfter.Group = "g"
	groupAfter.Warning = "group-after applied"
	other := l.job("other", true)
	other.Group = "h"
	ungrouped := l.job("ungrouped", false)

	var logs bytes.Buffer
	applied, err := ApplyJobs(zerolog.New(&logs), []NetworkJob{
		groupBefore, failed, groupAfter, other, ungrouped,
	})
	require.NoError(t, err)

	assert.Equal(t, []string{
		"apply group-before", "apply group-failed", "apply other", "apply ungrouped",
	}, l.ran, "a group job after the failure must be skipped")
	assert.Equal(t, []string{"group-before", "other", "ungrouped"},
		descriptions(applied),
		"the failed and the skipped jobs must be left out")
	assert.Contains(t, logs.String(), "an earlier job of its group failed")
	assert.Contains(t, logs.String(), `"job":"group-after"`)
	assert.NotContains(t, logs.String(), "group-after applied",
		"a skipped job's warning must not be logged")
}

func TestApplyJobs_GroupSkipsJobWithoutApply(t *testing.T) {
	var l actionLog
	failed := l.failingJob("failed", true)
	failed.Group = "g"
	resetOnly := NetworkJob{
		Description: "reset only",
		Reset:       fakeAction{name: "reset reset-only", log: &l},
		Group:       "g",
	}

	applied, err := ApplyJobs(zerolog.Nop(), []NetworkJob{failed, resetOnly})
	require.NoError(t, err)

	assert.Empty(t, applied, "a skipped job must not be reset")
}

func TestApplyJobs_JobWithoutApplyIsApplied(t *testing.T) {
	var l actionLog
	resetOnly := NetworkJob{
		Description: "reset only",
		Reset:       fakeAction{name: "reset reset-only", log: &l},
	}

	applied, err := ApplyJobs(zerolog.Nop(), []NetworkJob{resetOnly})
	require.NoError(t, err)

	assert.Empty(t, l.ran)
	assert.Equal(t, []string{"reset only"}, descriptions(applied))
}

func TestApplyJobs_RequiredFailureRollsBack(t *testing.T) {
	var l actionLog
	resetOnly := NetworkJob{
		Description: "reset only",
		Reset:       fakeAction{name: "reset reset-only", log: &l},
	}

	var logs bytes.Buffer
	applied, err := ApplyJobs(zerolog.New(&logs), []NetworkJob{
		resetOnly,
		l.job("first", false),
		l.job("second", false),
		l.failingJob("optional", true),
		l.failingJob("required", false),
		l.job("after", false),
	})

	require.EqualError(t, err, `job "required": apply required: failed`)
	assert.Nil(t, applied)
	assert.Equal(t, []string{
		"apply first", "apply second", "apply optional", "apply required",
		"reset second", "reset first", "reset reset-only",
	}, l.ran, "the jobs applied before the failed one are reset in LIFO order, "+
		"and the failed, the failed optional and the later jobs are not")
	assert.Contains(t, logs.String(), "restoring network configuration")
}

func TestApplyJobs_FirstJobFailureRollsBackNothing(t *testing.T) {
	var l actionLog

	var logs bytes.Buffer
	_, err := ApplyJobs(zerolog.New(&logs), []NetworkJob{
		l.failingJob("required", false),
		l.job("after", false),
	})

	require.Error(t, err)
	assert.Equal(t, []string{"apply required"}, l.ran)
	assert.NotContains(t, logs.String(), "restoring network configuration",
		"nothing to restore")
}

func TestResetJobs_LogsRestoreAndFailures(t *testing.T) {
	var l actionLog
	failingReset := NetworkJob{
		Description: "failing reset",
		Reset:       fakeAction{name: "reset failing", log: &l, err: errors.New("boom")},
	}
	later := l.job("later", false)

	var logs bytes.Buffer
	ResetJobs(zerolog.New(&logs), []NetworkJob{failingReset, later})

	out := logs.String()
	assert.Equal(t, []string{"reset later", "reset failing"}, l.ran,
		"jobs are reset in LIFO order, and a failure does not stop the reset")
	assert.Contains(t, out,
		`{"level":"warn","error":"boom","job":"failing reset",`+
			`"action":"reset failing","message":"network job reset failed (ignored)"}`)
	assert.Contains(t, out,
		`{"level":"info","jobs":2,"message":"restoring network configuration"}`)
	assert.Contains(t, out,
		`{"level":"info","jobs":2,"message":"network configuration restored"}`)
	assert.Contains(t, out,
		`{"level":"debug","job":"later","action":"reset later",`+
			`"message":"resetting network job"}`)
}

func TestResetJobs_NothingApplied(t *testing.T) {
	var logs bytes.Buffer
	ResetJobs(zerolog.New(&logs), nil)
	assert.Empty(t, logs.String())
}

func TestCommandAction_Run(t *testing.T) {
	require.NoError(t, CommandAction{"true"}.Run())

	err := CommandAction{"false"}.Run()
	require.EqualError(t, err, "exit status 1")

	// The argument reaches the command as is: no shell splits or expands it.
	err = CommandAction{"sh", "-c", `echo "$1"; exit 3`, "sh", "a  b; echo $HOME"}.Run()
	require.EqualError(t, err, "exit status 3: a  b; echo $HOME")

	require.Error(t, CommandAction{}.Run())
}

func TestCommandAction_String(t *testing.T) {
	a := CommandAction{"networksetup", "-setautoproxystate", "Wi-Fi", "off"}
	assert.Equal(t, "networksetup -setautoproxystate Wi-Fi off", a.String())
}
