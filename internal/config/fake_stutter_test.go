package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
