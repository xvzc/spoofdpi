package config

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runCmd runs the command with the given TOML file contents (none if empty)
// and extra args. It returns the loaded config, the warnings emitted while
// loading, and the run error.
func runCmd(t *testing.T, toml string, args ...string) (*Config, []string, error) {
	t.Helper()

	warnMu.Lock()
	WarnMsgs = nil
	warnMu.Unlock()
	t.Cleanup(func() {
		warnMu.Lock()
		WarnMsgs = nil
		warnMu.Unlock()
	})

	argv := []string{"spoofdpi"}
	if toml == "" {
		argv = append(argv, "--clean")
	} else {
		path := filepath.Join(t.TempDir(), "spoofdpi.toml")
		require.NoError(t, os.WriteFile(path, []byte(toml), 0o644))
		argv = append(argv, "--config", path)
	}
	argv = append(argv, args...)

	var captured *Config
	cmd := CreateCommand(
		func(_ context.Context, _ string, cfg *Config) error {
			captured = cfg
			return nil
		},
		"v0.0.0", "commit", "build",
	)
	err := cmd.Run(context.Background(), argv)

	warnMu.Lock()
	warns := append([]string(nil), WarnMsgs...)
	warnMu.Unlock()

	return captured, warns, err
}

// runWithTOML is runCmd for runs that must succeed.
func runWithTOML(t *testing.T, toml string, args ...string) (*Config, []string) {
	t.Helper()

	cfg, warns, err := runCmd(t, toml, args...)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	return cfg, warns
}

func TestTLSCompat_CLI(t *testing.T) {
	t.Run("tls flag", func(t *testing.T) {
		cfg, warns := runWithTOML(t, "", "--tls-fake-count", "3")
		assert.Equal(t, uint8(3), cfg.HTTPS.FakeCount)
		assert.Empty(t, warns)
	})

	t.Run("deprecated https flags still work and warn", func(t *testing.T) {
		cfg, warns := runWithTOML(t, "",
			"--https-fake-count", "3",
			"--https-split-mode", "chunk",
		)
		assert.Equal(t, uint8(3), cfg.HTTPS.FakeCount)
		assert.Equal(t, HTTPSSplitModeChunk, cfg.HTTPS.SplitMode)
		assert.Contains(t, warns,
			"'--https-fake-count' is deprecated; use '--tls-fake-count'")
		assert.Contains(t, warns,
			"'--https-split-mode' is deprecated; use '--tls-split-mode'")
	})

	// urfave/cli runs flag actions in map order, not argument order, so
	// check both orders.
	for _, args := range [][]string{
		{"--tls-fake-count", "5", "--https-fake-count", "3", "--https-chunk-size", "9"},
		{"--https-chunk-size", "9", "--https-fake-count", "3", "--tls-fake-count", "5"},
	} {
		t.Run("tls flag wins over the same https flag", func(t *testing.T) {
			cfg, _ := runWithTOML(t, "", args...)
			assert.Equal(t, uint8(5), cfg.HTTPS.FakeCount, "--tls-* wins")
			assert.Equal(t, uint8(9), cfg.HTTPS.ChunkSize,
				"an https flag without a tls counterpart still applies")
		})
	}

	t.Run("deprecated https flags override TOML", func(t *testing.T) {
		cfg, _ := runWithTOML(t, `
[tls]
fake-count = 5
disorder = true
skip = true
`,
			"--https-fake-count", "3",
			"--https-disorder=false",
			"--https-skip=false",
			"--https-fake-packet", "0xff,0xee",
		)
		assert.Equal(t, uint8(3), cfg.HTTPS.FakeCount)
		assert.False(t, cfg.HTTPS.Disorder)
		assert.False(t, cfg.HTTPS.Skip)
		assert.Equal(t, []byte{0xff, 0xee}, cfg.HTTPS.FakePacket.Raw())
	})

	t.Run("help lists tls flags only", func(t *testing.T) {
		var out bytes.Buffer
		cmd := CreateCommand(
			func(context.Context, string, *Config) error { return nil },
			"v0.0.0", "commit", "build",
		)
		cmd.Writer = &out
		require.NoError(t, cmd.Run(context.Background(), []string{"spoofdpi", "--help"}))

		assert.Contains(t, out.String(), "--tls-fake-count")
		assert.NotContains(t, out.String(), "--https-")
	})
}

func TestTLSCompat_TOML(t *testing.T) {
	t.Run("tls section", func(t *testing.T) {
		cfg, warns := runWithTOML(t, "[tls]\nfake-count = 3\n")
		assert.Equal(t, uint8(3), cfg.HTTPS.FakeCount)
		assert.Empty(t, warns)
	})

	t.Run("deprecated https section still works and warns", func(t *testing.T) {
		cfg, warns := runWithTOML(t, "[https]\nfake-count = 3\n")
		assert.Equal(t, uint8(3), cfg.HTTPS.FakeCount)
		assert.Contains(t, warns, "'[https]' is deprecated; rename to '[tls]'")
	})

	t.Run("https section is ignored when tls is set", func(t *testing.T) {
		cfg, warns := runWithTOML(t, `
[tls]
fake-count = 5

[https]
fake-count = 3
chunk-size = 9
split-mode = "custom"
`)
		assert.Equal(t, uint8(5), cfg.HTTPS.FakeCount)
		assert.Equal(
			t,
			uint8(35),
			cfg.HTTPS.ChunkSize,
			"keys only in [https] are ignored too",
		)
		assert.Equal(t, HTTPSSplitModeSNI, cfg.HTTPS.SplitMode,
			"an invalid [https] is not even parsed")
		assert.Contains(t, warns, "'[https]' is ignored because '[tls]' is set")
	})

	t.Run("type error names tls", func(t *testing.T) {
		_, _, err := runCmd(t, "tls = 1\n")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "'tls' must be table type")
	})
}

func TestTLSCompat_Rules(t *testing.T) {
	t.Run("tls in a rule", func(t *testing.T) {
		cfg, warns := runWithTOML(t, `
[[rules]]
name = "r"
match = { domains = ["example.com"] }
tls = { fake-count = 3 }
`)
		require.Len(t, cfg.Rules, 1)
		assert.Equal(t, uint8(3), cfg.Rules[0].Config.HTTPS.FakeCount)
		assert.Empty(t, warns)
	})

	t.Run("deprecated https in a rule still works and warns", func(t *testing.T) {
		cfg, warns := runWithTOML(t, `
[[rules]]
name = "r"
match = { domains = ["example.com"] }
https = { fake-count = 3 }
`)
		require.Len(t, cfg.Rules, 1)
		assert.Equal(t, uint8(3), cfg.Rules[0].Config.HTTPS.FakeCount)
		assert.Contains(t, warns, "rule 0: 'https' is deprecated; rename to 'tls'")
	})

	t.Run("https in a rule is ignored when tls is set", func(t *testing.T) {
		cfg, warns := runWithTOML(t, `
[[rules]]
name = "r"
match = { domains = ["example.com"] }
https = { fake-count = 3, chunk-size = 9, split-mode = "custom" }
tls = { fake-count = 5 }
`)
		require.Len(t, cfg.Rules, 1)
		assert.Equal(t, uint8(5), cfg.Rules[0].Config.HTTPS.FakeCount)
		assert.Equal(t, uint8(35), cfg.Rules[0].Config.HTTPS.ChunkSize,
			"keys only in https are ignored too")
		assert.Contains(t, warns, "rule 0: 'https' is ignored because 'tls' is set")
	})
}
