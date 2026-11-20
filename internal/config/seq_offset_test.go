package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
