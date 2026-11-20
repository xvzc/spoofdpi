package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
