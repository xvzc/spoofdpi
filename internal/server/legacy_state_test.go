//go:build unix

package server

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWarnLegacyStateFiles(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "regular.state")
	require.NoError(t, os.WriteFile(regular, []byte(`{"jobs":[]}`), 0o600))
	// A symlink to a file that does not exist counts: it is not followed.
	dangling := filepath.Join(dir, "dangling.state")
	require.NoError(t, os.Symlink(filepath.Join(dir, "nowhere"), dangling))
	// A FIFO counts too, and is not opened: opening it would block.
	fifo := filepath.Join(dir, "fifo.state")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	missing := filepath.Join(dir, "missing.state")
	odd := filepath.Join(dir, "odd\nname.state")
	require.NoError(t, os.WriteFile(odd, nil, 0o600))

	var logs bytes.Buffer
	warnLegacyStateFiles(
		zerolog.New(&logs),
		[]string{regular, dangling, fifo, missing, odd},
	)

	lines := strings.Split(strings.TrimSpace(logs.String()), "\n")
	require.Len(t, lines, 4)
	for _, line := range lines {
		assert.Contains(t, line, `"level":"warn"`)
		assert.Contains(t, line, "no longer used by spoofdpi")
		assert.Contains(t, line, "do not run the commands in it, delete it")
	}
	assert.Contains(t, lines[0], `\"`+regular+`\"`)
	assert.Contains(t, lines[1], `\"`+dangling+`\"`)
	assert.Contains(t, lines[2], `\"`+fifo+`\"`)
	assert.Contains(t, lines[3], `odd\\nname.state`,
		"the path is quoted, so a newline in it cannot start a log line")
	assert.NotContains(t, logs.String(), missing)

	for _, path := range []string{regular, dangling, fifo, odd} {
		_, err := os.Lstat(path)
		assert.NoError(t, err, "%s must be left in place", path)
	}
}
