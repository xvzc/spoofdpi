package config

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHopCountDefaultRename(t *testing.T) {
	t.Run("new flag", func(t *testing.T) {
		cfg, warns := runWithTOML(t, "", "--hop-count-default", "12")
		assert.Equal(t, uint8(12), cfg.Conn.HopCountDefault)
		assert.Empty(t, warns)
	})

	t.Run("deprecated flag still works and warns", func(t *testing.T) {
		cfg, warns := runWithTOML(t, "", "--default-fake-ttl", "12")
		assert.Equal(t, uint8(12), cfg.Conn.HopCountDefault)
		assert.Contains(
			t,
			warns,
			"'--default-fake-ttl' is deprecated; use '--hop-count-default'",
		)
	})

	// urfave/cli runs flag actions in map order, so check both orders.
	for _, args := range [][]string{
		{"--hop-count-default", "12", "--default-fake-ttl", "20"},
		{"--default-fake-ttl", "20", "--hop-count-default", "12"},
	} {
		t.Run("new flag wins over deprecated flag", func(t *testing.T) {
			cfg, _ := runWithTOML(t, "", args...)
			assert.Equal(t, uint8(12), cfg.Conn.HopCountDefault)
		})
	}

	t.Run("deprecated flag overrides TOML", func(t *testing.T) {
		cfg, _ := runWithTOML(
			t,
			"[connection]\nhop-count-default = 12\n",
			"--default-fake-ttl",
			"20",
		)
		assert.Equal(t, uint8(20), cfg.Conn.HopCountDefault)
	})

	t.Run("new TOML key", func(t *testing.T) {
		cfg, warns := runWithTOML(t, "[connection]\nhop-count-default = 12\n")
		assert.Equal(t, uint8(12), cfg.Conn.HopCountDefault)
		assert.Empty(t, warns)
	})

	t.Run("deprecated TOML key still works and warns", func(t *testing.T) {
		cfg, warns := runWithTOML(t, "[connection]\ndefault-fake-ttl = 12\n")
		assert.Equal(t, uint8(12), cfg.Conn.HopCountDefault)
		assert.Contains(
			t,
			warns,
			"'default-fake-ttl' is deprecated; rename to 'hop-count-default'",
		)
	})

	t.Run("deprecated TOML key is ignored when the new one is set", func(t *testing.T) {
		cfg, warns := runWithTOML(
			t,
			"[connection]\nhop-count-default = 12\ndefault-fake-ttl = 20\n",
		)
		assert.Equal(t, uint8(12), cfg.Conn.HopCountDefault)
		assert.Contains(
			t,
			warns,
			"'default-fake-ttl' is ignored because 'hop-count-default' is set",
		)
	})

	t.Run("rule connection section", func(t *testing.T) {
		cfg, warns := runWithTOML(t, `
[[rules]]
name = "r"
match = { domains = ["example.com"] }
connection = { default-fake-ttl = 20 }
`)
		require.Len(t, cfg.Rules, 1)
		assert.Equal(t, uint8(20), cfg.Rules[0].Config.Conn.HopCountDefault)
		assert.Contains(
			t,
			warns,
			"'default-fake-ttl' is deprecated; rename to 'hop-count-default'",
		)
	})

	t.Run("help lists the new flag only", func(t *testing.T) {
		var out bytes.Buffer
		cmd := CreateCommand(
			func(context.Context, string, *Config) error { return nil },
			"v0.0.0", "commit", "build",
		)
		cmd.Writer = &out
		require.NoError(t, cmd.Run(context.Background(), []string{"spoofdpi", "--help"}))
		assert.Contains(t, out.String(), "--hop-count-default")
		assert.NotContains(t, out.String(), "--default-fake-ttl")
	})
}

func TestHopCountOptions(t *testing.T) {
	t.Run("defaults keep the previous behavior", func(t *testing.T) {
		cfg, _ := runWithTOML(t, "")
		assert.Equal(t, uint8(8), cfg.Conn.HopCountDefault)
		assert.Equal(t, uint8(0), cfg.Conn.HopCountMin)
		assert.Equal(t, uint8(255), cfg.Conn.HopCountMax)
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
