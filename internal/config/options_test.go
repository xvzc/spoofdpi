package config

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

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
		cfg, warns := runWithTOML(t, "", "--tls-fake-preflight", "3")
		assert.Equal(t, uint8(3), cfg.HTTPS.FakePreflight)
		assert.Empty(t, warns)
	})

	t.Run("deprecated https flags still work and warn", func(t *testing.T) {
		cfg, warns := runWithTOML(t, "",
			"--https-fake-count", "3",
			"--https-split-mode", "chunk",
		)
		assert.Equal(t, uint8(3), cfg.HTTPS.FakePreflight)
		assert.Equal(t, HTTPSSplitModeChunk, cfg.HTTPS.SplitMode)
		assert.Contains(t, warns,
			"'--https-fake-count' is deprecated; use '--tls-fake-preflight'")
		assert.Contains(t, warns,
			"'--https-split-mode' is deprecated; use '--tls-split-mode'")
	})

	// urfave/cli runs flag actions in map order, not argument order, so
	// check both orders.
	for _, args := range [][]string{
		{"--tls-fake-preflight", "5", "--https-fake-count", "3", "--https-disorder"},
		{"--https-disorder", "--https-fake-count", "3", "--tls-fake-preflight", "5"},
	} {
		t.Run("tls flag wins over the same https flag", func(t *testing.T) {
			cfg, _ := runWithTOML(t, "", args...)
			assert.Equal(t, uint8(5), cfg.HTTPS.FakePreflight, "--tls-* wins")
			assert.True(t, cfg.HTTPS.Disorder,
				"an https flag without a tls value still applies")
		})
	}

	t.Run("deprecated https flags override TOML", func(t *testing.T) {
		cfg, _ := runWithTOML(t, `
[tls]
fake-preflight = 5
disorder = true
skip = true
`,
			"--https-fake-count", "3",
			"--https-disorder=false",
			"--https-skip=false",
			"--https-fake-packet", "0xff,0xee",
		)
		assert.Equal(t, uint8(3), cfg.HTTPS.FakePreflight)
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

		assert.Contains(t, out.String(), "--tls-fake-preflight")
		assert.NotContains(t, out.String(), "--https-")
	})
}

func TestTLSCompat_TOML(t *testing.T) {
	t.Run("tls section", func(t *testing.T) {
		cfg, warns := runWithTOML(t, "[tls]\nfake-preflight = 3\n")
		assert.Equal(t, uint8(3), cfg.HTTPS.FakePreflight)
		assert.Empty(t, warns)
	})

	t.Run("deprecated https section still works and warns", func(t *testing.T) {
		cfg, warns := runWithTOML(t, "[https]\nfake-preflight = 3\n")
		assert.Equal(t, uint8(3), cfg.HTTPS.FakePreflight)
		assert.Contains(t, warns, "'[https]' is deprecated; rename to '[tls]'")
	})

	t.Run("https section is ignored when tls is set", func(t *testing.T) {
		cfg, warns := runWithTOML(t, `
[tls]
fake-preflight = 5

[https]
fake-preflight = 3
chunk-size = 9
split-mode = "custom"
`)
		assert.Equal(t, uint8(5), cfg.HTTPS.FakePreflight)
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
tls = { fake-preflight = 3 }
`)
		require.Len(t, cfg.Rules, 1)
		assert.Equal(t, uint8(3), cfg.Rules[0].Config.HTTPS.FakePreflight)
		assert.Empty(t, warns)
	})

	t.Run("deprecated https in a rule still works and warns", func(t *testing.T) {
		cfg, warns := runWithTOML(t, `
[[rules]]
name = "r"
match = { domains = ["example.com"] }
https = { fake-preflight = 3 }
`)
		require.Len(t, cfg.Rules, 1)
		assert.Equal(t, uint8(3), cfg.Rules[0].Config.HTTPS.FakePreflight)
		assert.Contains(t, warns, "rule 0: 'https' is deprecated; rename to 'tls'")
	})

	t.Run("https in a rule is ignored when tls is set", func(t *testing.T) {
		cfg, warns := runWithTOML(t, `
[[rules]]
name = "r"
match = { domains = ["example.com"] }
https = { fake-count = 3, chunk-size = 9, split-mode = "custom" }
tls = { fake-preflight = 5 }
`)
		require.Len(t, cfg.Rules, 1)
		assert.Equal(t, uint8(5), cfg.Rules[0].Config.HTTPS.FakePreflight)
		assert.Equal(t, uint8(35), cfg.Rules[0].Config.HTTPS.ChunkSize,
			"keys only in https are ignored too")
		assert.Contains(t, warns, "rule 0: 'https' is ignored because 'tls' is set")
	})
}

func TestFakeBadMD5SigOption(t *testing.T) {
	t.Run("default off", func(t *testing.T) {
		cfg, _ := runWithTOML(t, "")
		assert.False(t, cfg.HTTPS.FakeBadMD5Sig)
	})

	t.Run("cli", func(t *testing.T) {
		cfg, warns := runWithTOML(t, "", "--tls-fake-bad-md5sig")
		assert.True(t, cfg.HTTPS.FakeBadMD5Sig)
		assert.Empty(t, warns)
	})

	t.Run("toml and rule", func(t *testing.T) {
		cfg, _ := runWithTOML(t, `
[tls]
fake-bad-md5sig = true

[[rules]]
name = "r"
match = { domains = ["example.com"] }
tls = { fake-bad-md5sig = false }
`)
		assert.True(t, cfg.HTTPS.FakeBadMD5Sig)
		require.Len(t, cfg.Rules, 1)
		assert.False(t, cfg.Rules[0].Config.HTTPS.FakeBadMD5Sig)
	})

	t.Run("cli overrides toml", func(t *testing.T) {
		cfg, _ := runWithTOML(
			t,
			"[tls]\nfake-bad-md5sig = true\n",
			"--tls-fake-bad-md5sig=false",
		)
		assert.False(t, cfg.HTTPS.FakeBadMD5Sig)
	})

	t.Run("invalid values and https alias", func(t *testing.T) {
		_, _, err := runCmd(t, "[tls]\nfake-bad-md5sig = 1\n")
		assert.Error(t, err)
		_, _, err = runCmd(t, "", "--https-fake-bad-md5sig")
		assert.Error(t, err, "new option has no --https-* alias")
	})
}

func TestFakeStutterOption(t *testing.T) {
	t.Run("default off", func(t *testing.T) {
		cfg, _ := runWithTOML(t, "")
		assert.Equal(t, uint8(0), cfg.HTTPS.FakeStutter)
		assert.False(t, cfg.HTTPS.UsesFakes())
		assert.False(t, cfg.NeedsTCPStack())
	})

	t.Run("cli", func(t *testing.T) {
		cfg, warns := runWithTOML(t, "", "--tls-fake-stutter", "2")
		assert.Equal(t, uint8(2), cfg.HTTPS.FakeStutter)
		assert.True(t, cfg.HTTPS.UsesFakes())
		assert.True(t, cfg.NeedsTCPStack(), "stutter alone needs packet capture")
		assert.Empty(t, warns)
	})

	t.Run("toml and rule", func(t *testing.T) {
		cfg, _ := runWithTOML(t, `
[tls]
fake-stutter = 2

[[rules]]
name = "r"
match = { domains = ["example.com"] }
tls = { fake-stutter = 3 }
`)
		assert.Equal(t, uint8(2), cfg.HTTPS.FakeStutter)
		require.Len(t, cfg.Rules, 1)
		assert.Equal(t, uint8(3), cfg.Rules[0].Config.HTTPS.FakeStutter)
	})

	t.Run("rule-only stutter needs packet capture", func(t *testing.T) {
		cfg, _ := runWithTOML(t, `
[[rules]]
name = "r"
match = { domains = ["example.com"] }
tls = { fake-stutter = 1 }
`)
		assert.True(t, cfg.NeedsTCPStack())
	})

	t.Run("invalid and deprecated names", func(t *testing.T) {
		_, _, err := runCmd(t, "", "--tls-fake-stutter", "256")
		assert.Error(t, err)
		_, _, err = runCmd(t, "", "--https-fake-stutter", "1")
		assert.Error(t, err, "new option has no --https-* alias")
	})
}

func TestFakeSeqOffsetOptions(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		cfg, _ := runWithTOML(t, "")
		assert.Equal(t, int64(0), cfg.HTTPS.FakeSeqOffset)
		assert.Equal(t, int64(0), cfg.HTTPS.FakeAckOffset)
		assert.Equal(t, 100*time.Millisecond, cfg.HTTPS.SynAckTimeout)
	})

	t.Run("cli", func(t *testing.T) {
		cfg, _ := runWithTOML(t, "",
			"--tls-fake-seq-offset", "-10000",
			"--tls-fake-ack-offset=-1073741824",
			"--tls-syn-ack-timeout", "0",
		)
		assert.Equal(
			t,
			int64(-10000),
			cfg.HTTPS.FakeSeqOffset,
			"negative value after a space",
		)
		assert.Equal(t, int64(-1073741824), cfg.HTTPS.FakeAckOffset)
		assert.Equal(t, time.Duration(0), cfg.HTTPS.SynAckTimeout)
	})

	t.Run("toml and rule", func(t *testing.T) {
		cfg, _ := runWithTOML(t, `
[tls]
fake-seq-offset = 10
fake-ack-offset = 66000
syn-ack-timeout = 50

[[rules]]
name = "r"
match = { domains = ["example.com"] }
tls = { fake-seq-offset = -10000 }
`)
		assert.Equal(t, int64(10), cfg.HTTPS.FakeSeqOffset)
		assert.Equal(t, int64(66000), cfg.HTTPS.FakeAckOffset)
		assert.Equal(t, 50*time.Millisecond, cfg.HTTPS.SynAckTimeout)

		require.Len(t, cfg.Rules, 1)
		r := cfg.Rules[0].Config.HTTPS
		assert.Equal(t, int64(-10000), r.FakeSeqOffset)
		assert.Equal(t, int64(66000), r.FakeAckOffset, "rule inherits fake-ack-offset")
		assert.Equal(
			t,
			50*time.Millisecond,
			r.SynAckTimeout,
			"rule inherits syn-ack-timeout",
		)
	})

	t.Run("range is |N| < 2^32", func(t *testing.T) {
		for _, v := range []string{"4294967295", "-4294967295"} {
			_, _, err := runCmd(t, "", "--tls-fake-seq-offset="+v)
			assert.NoError(t, err, v)
		}
		for _, v := range []string{"4294967296", "-4294967296", "abc", "1.5"} {
			_, _, err := runCmd(t, "", "--tls-fake-seq-offset="+v)
			assert.Error(t, err, v)
		}
		_, _, err := runCmd(t, "[tls]\nfake-ack-offset = 4294967296\n")
		assert.Error(t, err)
		_, _, err = runCmd(t, "[tls]\nfake-ack-offset = \"offset:0\"\n")
		assert.Error(t, err, "string values are rejected")
		_, _, err = runCmd(t, "", "--tls-syn-ack-timeout", "70000")
		assert.Error(t, err)
	})

	t.Run("old names and https aliases do not exist", func(t *testing.T) {
		for _, flag := range []string{
			"--tls-fake-seq", "--tls-fake-ack",
			"--https-fake-seq-offset", "--https-fake-ack-offset", "--https-syn-ack-timeout",
		} {
			_, _, err := runCmd(t, "", flag, "1")
			assert.Error(t, err, flag)
		}
	})
}

func TestHopCountOptions(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		cfg, _ := runWithTOML(t, "")
		assert.Equal(t, uint8(8), cfg.Conn.HopCountDefault)
		assert.Equal(t, uint8(0), cfg.Conn.HopCountMin)
		assert.Equal(t, uint8(255), cfg.Conn.HopCountMax)
		assert.Equal(t, int8(-1), cfg.Conn.HopCountOffset)
	})

	t.Run("rule inherits the default offset", func(t *testing.T) {
		cfg, _ := runWithTOML(t, `
[[rules]]
name = "r"
match = { domains = ["example.com"] }
connection = { hop-count-max = 12 }
`)
		require.Len(t, cfg.Rules, 1)
		assert.Equal(t, int8(-1), cfg.Rules[0].Config.Conn.HopCountOffset)
	})

	t.Run("zero offset overrides the default", func(t *testing.T) {
		cfg, _ := runWithTOML(t, `
[connection]
hop-count-offset = 0

[[rules]]
name = "r"
match = { domains = ["example.com"] }
connection = { hop-count-offset = -3 }
`)
		assert.Equal(t, int8(0), cfg.Conn.HopCountOffset)
		require.Len(t, cfg.Rules, 1)
		assert.Equal(t, int8(-3), cfg.Rules[0].Config.Conn.HopCountOffset)

		cfg, _ = runWithTOML(t, "", "--hop-count-offset", "0")
		assert.Equal(t, int8(0), cfg.Conn.HopCountOffset)
	})

	t.Run("cli", func(t *testing.T) {
		cfg, _ := runWithTOML(t, "",
			"--hop-count-min", "3",
			"--hop-count-max", "20",
			"--hop-count-offset=-5",
		)
		assert.Equal(t, uint8(3), cfg.Conn.HopCountMin)
		assert.Equal(t, uint8(20), cfg.Conn.HopCountMax)
		assert.Equal(t, int8(-5), cfg.Conn.HopCountOffset)
	})

	t.Run("cli negative offset as a separate argument", func(t *testing.T) {
		cfg, _, err := runCmd(t, "", "--hop-count-offset", "-5")
		require.NoError(t, err)
		assert.Equal(t, int8(-5), cfg.Conn.HopCountOffset)
	})

	t.Run("toml and rule", func(t *testing.T) {
		cfg, _ := runWithTOML(t, `
[connection]
hop-count-min = 3
hop-count-max = 20
hop-count-offset = -5

[[rules]]
name = "r"
match = { domains = ["example.com"] }
connection = { hop-count-max = 12 }
`)
		assert.Equal(t, uint8(3), cfg.Conn.HopCountMin)
		assert.Equal(t, uint8(20), cfg.Conn.HopCountMax)
		assert.Equal(t, int8(-5), cfg.Conn.HopCountOffset)
		require.Len(t, cfg.Rules, 1)
		assert.Equal(t, uint8(12), cfg.Rules[0].Config.Conn.HopCountMax)
		assert.Equal(t, int8(-5), cfg.Rules[0].Config.Conn.HopCountOffset, "rule inherits")
	})

	t.Run("invalid values are rejected", func(t *testing.T) {
		for _, args := range [][]string{
			{"--hop-count-max", "0"},
			{"--hop-count-max", "256"},
			{"--hop-count-min", "-1"},
			{"--hop-count-offset", "200"},
			{"--hop-count-min", "20", "--hop-count-max", "10"},
		} {
			_, _, err := runCmd(t, "", args...)
			assert.Error(t, err, args)
		}
		_, _, err := runCmd(t, "[connection]\nhop-count-min = 20\nhop-count-max = 10\n")
		assert.Error(t, err)
	})
}
