//go:build darwin || linux || freebsd

package server

import (
	"bytes"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/executil"
)

// savedMarkerState saves a state whose Apply and Reset create files in dir and
// returns its path. Neither file exists after a refused state is processed.
func savedMarkerState(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "state")
	job := fileJob(dir, "applied", false)
	job.Reset = "touch " + executil.Quote(filepath.Join(dir, "reset"))
	require.NoError(t, SaveJobs(path, []NetworkJob{job}, SurvivesReboot))
	return path
}

func TestLoadJobs_AcceptsOwnPrivateFile(t *testing.T) {
	dir := t.TempDir()
	path := savedMarkerState(t, dir)

	jobs, exists, err := LoadJobs(path)

	require.NoError(t, err)
	assert.True(t, exists)
	assert.Len(t, jobs, 1)
}

func TestLoadJobs_RefusesUntrustedFile(t *testing.T) {
	tests := []struct {
		name  string
		plant func(t *testing.T, dir, path string)
	}{
		{"symlink", func(t *testing.T, dir, path string) {
			target := savedMarkerState(t, t.TempDir())
			require.NoError(t, os.Symlink(target, path))
		}},
		{"group writable", func(t *testing.T, dir, path string) {
			require.NoError(t, os.Chmod(savedMarkerState(t, dir), 0o664))
		}},
		{"world writable", func(t *testing.T, dir, path string) {
			require.NoError(t, os.Chmod(savedMarkerState(t, dir), 0o646))
		}},
		{"foreign owner", func(t *testing.T, dir, path string) {
			savedMarkerState(t, dir)
			orig := effectiveUID
			effectiveUID = func() int { return os.Geteuid() + 1 }
			t.Cleanup(func() { effectiveUID = orig })
		}},
		{"directory", func(t *testing.T, dir, path string) {
			require.NoError(t, os.Mkdir(path, 0o755))
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "state")
			tt.plant(t, dir, path)

			jobs, exists, err := LoadJobs(path)

			require.ErrorIs(t, err, errUntrustedState)
			assert.Contains(t, err.Error(), path)
			assert.False(t, exists)
			assert.Empty(t, jobs)
			_, statErr := os.Lstat(path)
			assert.NoError(t, statErr, "refused file must be left in place")
		})
	}
}

func TestApplyAndResetJobs_RefusedFileRunsNothing(t *testing.T) {
	dir := t.TempDir()
	path := savedMarkerState(t, dir)
	require.NoError(t, os.Chmod(path, 0o666))

	err := ApplyJobs(zerolog.Nop(), path)
	require.ErrorIs(t, err, errUntrustedState)

	var logs bytes.Buffer
	logger := zerolog.New(&logs)
	ResetJobs(logger, path)
	ResetStaleJobs(logger, path)

	assert.False(t, fileExists(dir, "applied"))
	assert.False(t, fileExists(dir, "reset"))
	assert.FileExists(t, path)
	assert.Contains(t, logs.String(), `"level":"warn"`)
	assert.Contains(t, logs.String(), path)
	assert.Contains(t, logs.String(), "untrusted state file")
}

func TestSaveJobs_RenameErrorIsReturned(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state")
	// A non-empty directory at path makes the rename fail.
	require.NoError(t, os.Mkdir(path, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(path, "keep"), nil, 0o644))

	err := SaveJobs(path, nil, SurvivesReboot)

	assert.Error(t, err)
}

func TestLoadJobs_RefusesFileSwappedAfterCheck(t *testing.T) {
	tests := []struct {
		name string
		swap func(t *testing.T, path string)
	}{
		{"symlink", func(t *testing.T, path string) {
			target := savedMarkerState(t, t.TempDir())
			require.NoError(t, os.Symlink(target, path))
		}},
		{"world writable file", func(t *testing.T, path string) {
			require.NoError(t, os.WriteFile(path, []byte("{}"), 0o600))
			require.NoError(t, os.Chmod(path, 0o666))
		}},
		{"fifo", func(t *testing.T, path string) {
			require.NoError(t, syscall.Mkfifo(path, 0o600))
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := savedMarkerState(t, dir)
			orig := beforeStateFileOpen
			beforeStateFileOpen = func(p string) {
				require.NoError(t, os.Remove(p))
				tt.swap(t, p)
			}
			t.Cleanup(func() { beforeStateFileOpen = orig })

			_, exists, err := LoadJobs(path)

			require.ErrorIs(t, err, errUntrustedState)
			assert.False(t, exists)
		})
	}
}

func TestResetStaleJobs_RefusesHardLinkedFile(t *testing.T) {
	dir := t.TempDir()
	path := savedMarkerState(t, dir)
	require.NoError(t, os.Link(path, path+".link"))

	var logs bytes.Buffer
	ResetStaleJobs(zerolog.New(&logs), path)

	assert.False(t, fileExists(dir, "reset"))
	assert.FileExists(t, path)
	assert.Contains(t, logs.String(), `"level":"warn"`)
	assert.Contains(t, logs.String(), path)
	assert.Contains(t, logs.String(), "hard links")
}

func TestResetJobs_ResetsHardLinkedFile(t *testing.T) {
	dir := t.TempDir()
	path := savedMarkerState(t, dir)
	require.NoError(t, os.Link(path, path+".link"))

	ResetJobs(zerolog.Nop(), path)

	assert.True(t, fileExists(dir, "reset"))
	_, err := os.Lstat(path)
	assert.True(t, os.IsNotExist(err))
}
