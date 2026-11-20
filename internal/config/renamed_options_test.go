package config

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFakePreflightRename(t *testing.T) {
	t.Run("new flags", func(t *testing.T) {
		cfg, warns := runWithTOML(
			t,
			"",
			"--tls-fake-preflight",
			"3",
			"--udp-fake-preflight",
			"4",
		)
		assert.Equal(t, uint8(3), cfg.HTTPS.FakePreflight)
		assert.Equal(t, uint8(4), cfg.UDP.FakePreflight)
		assert.Empty(t, warns)
	})

	t.Run("deprecated flags still work and warn", func(t *testing.T) {
		cfg, warns := runWithTOML(t, "", "--tls-fake-count", "3", "--udp-fake-count", "4")
		assert.Equal(t, uint8(3), cfg.HTTPS.FakePreflight)
		assert.Equal(t, uint8(4), cfg.UDP.FakePreflight)
		assert.Contains(
			t,
			warns,
			"'--tls-fake-count' is deprecated; use '--tls-fake-preflight'",
		)
		assert.Contains(
			t,
			warns,
			"'--udp-fake-count' is deprecated; use '--udp-fake-preflight'",
		)

		// Separate run: two deprecated names for one option apply in no
		// defined order.
		cfg, warns = runWithTOML(t, "", "--https-fake-count", "5")
		assert.Equal(t, uint8(5), cfg.HTTPS.FakePreflight)
		assert.Contains(
			t,
			warns,
			"'--https-fake-count' is deprecated; use '--tls-fake-preflight'",
		)
	})

	for _, args := range [][]string{
		{"--tls-fake-preflight", "3", "--tls-fake-count", "9"},
		{"--tls-fake-count", "9", "--tls-fake-preflight", "3"},
	} {
		t.Run("new flag wins", func(t *testing.T) {
			cfg, _ := runWithTOML(t, "", args...)
			assert.Equal(t, uint8(3), cfg.HTTPS.FakePreflight)
		})
	}

	t.Run("toml", func(t *testing.T) {
		cfg, warns := runWithTOML(
			t,
			"[tls]\nfake-preflight = 3\n[udp]\nfake-preflight = 4\n",
		)
		assert.Equal(t, uint8(3), cfg.HTTPS.FakePreflight)
		assert.Equal(t, uint8(4), cfg.UDP.FakePreflight)
		assert.Empty(t, warns)
	})

	t.Run("deprecated toml keys still work and warn", func(t *testing.T) {
		cfg, warns := runWithTOML(t, "[tls]\nfake-count = 3\n[udp]\nfake-count = 4\n")
		assert.Equal(t, uint8(3), cfg.HTTPS.FakePreflight)
		assert.Equal(t, uint8(4), cfg.UDP.FakePreflight)
		assert.Contains(t, warns, "'fake-count' is deprecated; rename to 'fake-preflight'")
	})

	t.Run("deprecated toml key is ignored when the new one is set", func(t *testing.T) {
		cfg, warns := runWithTOML(t, "[tls]\nfake-preflight = 3\nfake-count = 9\n")
		assert.Equal(t, uint8(3), cfg.HTTPS.FakePreflight)
		assert.Contains(t, warns, "'fake-count' is ignored because 'fake-preflight' is set")
	})

	t.Run("rule", func(t *testing.T) {
		cfg, warns := runWithTOML(t, `
[[rules]]
name = "r"
match = { domains = ["example.com"] }
tls = { fake-count = 3 }
`)
		require.Len(t, cfg.Rules, 1)
		assert.Equal(t, uint8(3), cfg.Rules[0].Config.HTTPS.FakePreflight)
		assert.Contains(
			t,
			warns,
			"rule 0: 'fake-count' is deprecated; rename to 'fake-preflight'",
		)
	})
}

func TestSplitModeChunkSize(t *testing.T) {
	t.Run("chunk:N sets the size", func(t *testing.T) {
		cfg, warns := runWithTOML(t, "", "--tls-split-mode", "chunk:12")
		assert.Equal(t, HTTPSSplitModeChunk, cfg.HTTPS.SplitMode)
		assert.Equal(t, uint8(12), cfg.HTTPS.ChunkSize)
		assert.Empty(t, warns)
	})

	t.Run("toml chunk:N", func(t *testing.T) {
		cfg, _ := runWithTOML(t, "[tls]\nsplit-mode = \"chunk:12\"\n")
		assert.Equal(t, uint8(12), cfg.HTTPS.ChunkSize)
	})

	t.Run("chunk alone always uses the default size", func(t *testing.T) {
		cfg, _ := runWithTOML(t, "[tls]\nsplit-mode = \"chunk\"\n")
		assert.Equal(t, HTTPSSplitModeChunk, cfg.HTTPS.SplitMode)
		assert.Equal(t, DefaultChunkSize, cfg.HTTPS.ChunkSize)

		cfg, _ = runWithTOML(
			t,
			"[tls]\nsplit-mode = \"chunk:12\"\n",
			"--tls-split-mode",
			"chunk",
		)
		assert.Equal(t, DefaultChunkSize, cfg.HTTPS.ChunkSize, "not the TOML size")

		cfg, _ = runWithTOML(t, `
[tls]
split-mode = "chunk:1"

[[rules]]
name = "r"
match = { domains = ["example.com"] }
tls = { split-mode = "chunk" }
`)
		require.Len(t, cfg.Rules, 1)
		assert.Equal(
			t,
			DefaultChunkSize,
			cfg.Rules[0].Config.HTTPS.ChunkSize,
			"not the base size",
		)
	})

	t.Run("invalid values are rejected", func(t *testing.T) {
		for _, v := range []string{"chunk:0", "chunk:256", "chunk:abc", "chunk:", "chunk=12", "sni:3"} {
			_, _, err := runCmd(t, "", "--tls-split-mode", v)
			assert.Error(t, err, v)
			_, _, err = runCmd(t, "[tls]\nsplit-mode = \""+v+"\"\n")
			assert.Error(t, err, v)
		}
	})

	t.Run("chunk-size is ignored with a warning", func(t *testing.T) {
		const msg = "'chunk-size' is no longer supported and is ignored; " +
			"use 'split-mode = \"chunk:N\"'"
		for _, toml := range []string{
			"[tls]\nsplit-mode = \"chunk\"\nchunk-size = 12\n",
			"[https]\nsplit-mode = \"chunk\"\nchunk-size = 12\n",
			"[tls]\nsplit-mode = \"chunk:20\"\nchunk-size = 12\n",
		} {
			cfg, warns := runWithTOML(t, toml)
			assert.NotEqual(t, uint8(12), cfg.HTTPS.ChunkSize, toml)
			assert.Contains(t, warns, msg, toml)
		}

		cfg, warns := runWithTOML(t, `
[[rules]]
name = "r"
match = { domains = ["example.com"] }
tls = { split-mode = "chunk", chunk-size = 12 }
`)
		assert.Equal(t, DefaultChunkSize, cfg.Rules[0].Config.HTTPS.ChunkSize)
		assert.Contains(t, warns, "rule 0: "+msg)
	})

	t.Run("--https-chunk-size is ignored with a warning", func(t *testing.T) {
		cfg, warns := runWithTOML(
			t,
			"",
			"--tls-split-mode",
			"chunk",
			"--https-chunk-size",
			"12",
		)
		assert.Equal(t, DefaultChunkSize, cfg.HTTPS.ChunkSize)
		assert.Contains(t, warns,
			"'--https-chunk-size' is no longer supported and is ignored; "+
				"use '--tls-split-mode chunk:N'")
	})

	t.Run("--tls-chunk-size does not exist", func(t *testing.T) {
		_, _, err := runCmd(t, "", "--tls-chunk-size", "12")
		assert.Error(t, err)
	})
}

func TestCustomSplitRename(t *testing.T) {
	const plans = `{ from = "head", at = 1 }, { from = "sni", at = 2, lazy = true }`

	t.Run("custom-split", func(t *testing.T) {
		cfg, warns := runWithTOML(
			t,
			"[tls]\nsplit-mode = \"custom\"\ncustom-split = ["+plans+"]\n",
		)
		assert.Len(t, cfg.HTTPS.CustomSplit, 2)
		assert.Empty(t, warns)
	})

	t.Run("deprecated custom-segments still works and warns", func(t *testing.T) {
		cfg, warns := runWithTOML(
			t,
			"[tls]\nsplit-mode = \"custom\"\ncustom-segments = ["+plans+"]\n",
		)
		assert.Len(t, cfg.HTTPS.CustomSplit, 2)
		assert.Contains(
			t,
			warns,
			"'custom-segments' is deprecated; rename to 'custom-split'",
		)
	})

	t.Run("custom-segments is ignored when custom-split is set", func(t *testing.T) {
		cfg, warns := runWithTOML(
			t,
			"[tls]\nsplit-mode = \"custom\"\ncustom-split = [{ from = \"head\", at = 1 }]\ncustom-segments = ["+plans+"]\n",
		)
		assert.Len(t, cfg.HTTPS.CustomSplit, 1)
		assert.Contains(
			t,
			warns,
			"'custom-segments' is ignored because 'custom-split' is set",
		)
	})

	t.Run("custom without custom-split is an error", func(t *testing.T) {
		_, _, err := runCmd(t, "[tls]\nsplit-mode = \"custom\"\n")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "custom-split must be provided")
	})
}

func TestRenamedFlagsHiddenFromHelp(t *testing.T) {
	var out bytes.Buffer
	cmd := CreateCommand(
		func(context.Context, string, *Config) error { return nil },
		"v0.0.0", "commit", "build",
	)
	cmd.Writer = &out
	require.NoError(t, cmd.Run(context.Background(), []string{"spoofdpi", "--help"}))

	for _, name := range []string{"--tls-fake-preflight", "--udp-fake-preflight", "--tls-split-mode"} {
		assert.Contains(t, out.String(), name)
	}
	for _, name := range []string{"--tls-fake-count", "--udp-fake-count", "--https-chunk-size"} {
		assert.NotContains(t, out.String(), name+" ")
	}
	assert.Contains(t, out.String(), "chunk:N")
}
