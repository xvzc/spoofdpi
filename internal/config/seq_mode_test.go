package config

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSeqMode(t *testing.T) {
	tcs := []struct {
		in      string
		want    SeqMode
		wantErr bool
	}{
		{"rand", SeqMode{Random: true}, false},
		{"offset:0", SeqMode{}, false},
		{"offset:-10000", SeqMode{Offset: -10000}, false},
		{"offset:66000", SeqMode{Offset: 66000}, false},
		{"offset:4294967295", SeqMode{Offset: 1<<32 - 1}, false},
		{"offset:-4294967295", SeqMode{Offset: -(1<<32 - 1)}, false},
		{"offset:4294967296", SeqMode{}, true},
		{"offset:-4294967296", SeqMode{}, true},
		{"offset:", SeqMode{}, true},
		{"offset:abc", SeqMode{}, true},
		{"offset:1.5", SeqMode{}, true},
		{"random", SeqMode{}, true},
		{"", SeqMode{}, true},
	}

	for _, tc := range tcs {
		t.Run(tc.in, func(t *testing.T) {
			got, err := parseSeqMode(tc.in)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.in, got.String(), "String round-trips")
		})
	}
}

func TestFakeSeqOptions(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		cfg, _ := runWithTOML(t, "")
		assert.Equal(t, SeqMode{}, cfg.HTTPS.FakeSeq)
		assert.Equal(t, SeqMode{}, cfg.HTTPS.FakeAck)
		assert.Equal(t, 100*time.Millisecond, cfg.HTTPS.SynAckTimeout)
	})

	t.Run("cli", func(t *testing.T) {
		cfg, _ := runWithTOML(t, "",
			"--tls-fake-seq", "offset:-10000",
			"--tls-fake-ack", "rand",
			"--tls-syn-ack-timeout", "0",
		)
		assert.Equal(t, SeqMode{Offset: -10000}, cfg.HTTPS.FakeSeq)
		assert.Equal(t, SeqMode{Random: true}, cfg.HTTPS.FakeAck)
		assert.Equal(t, time.Duration(0), cfg.HTTPS.SynAckTimeout)
	})

	t.Run("toml and rule", func(t *testing.T) {
		cfg, _ := runWithTOML(t, `
[tls]
fake-seq = "rand"
fake-ack = "offset:66000"
syn-ack-timeout = 50

[[rules]]
name = "r"
match = { domains = ["example.com"] }
tls = { fake-seq = "offset:-10000" }
`)
		assert.Equal(t, SeqMode{Random: true}, cfg.HTTPS.FakeSeq)
		assert.Equal(t, SeqMode{Offset: 66000}, cfg.HTTPS.FakeAck)
		assert.Equal(t, 50*time.Millisecond, cfg.HTTPS.SynAckTimeout)

		require.Len(t, cfg.Rules, 1)
		r := cfg.Rules[0].Config.HTTPS
		assert.Equal(t, SeqMode{Offset: -10000}, r.FakeSeq)
		assert.Equal(t, SeqMode{Offset: 66000}, r.FakeAck, "rule inherits fake-ack")
		assert.Equal(
			t,
			50*time.Millisecond,
			r.SynAckTimeout,
			"rule inherits syn-ack-timeout",
		)
	})

	t.Run("invalid values are rejected", func(t *testing.T) {
		_, _, err := runCmd(t, "", "--tls-fake-seq", "offset:x")
		assert.Error(t, err)
		_, _, err = runCmd(t, "[tls]\nfake-ack = \"bad\"\n")
		assert.Error(t, err)
		_, _, err = runCmd(t, "", "--tls-syn-ack-timeout", "70000")
		assert.Error(t, err)
	})

	t.Run("no deprecated https names", func(t *testing.T) {
		for _, flag := range []string{
			"--https-fake-seq", "--https-fake-ack", "--https-syn-ack-timeout",
		} {
			_, _, err := runCmd(t, "", flag, "1")
			assert.Error(t, err, flag)
		}
	})
}

func TestFakeSeqOverlapWarning(t *testing.T) {
	const warnPart = "'fake-seq' offset"

	tcs := []struct {
		name     string
		toml     string
		wantWarn bool
	}{
		{
			"small negative offset",
			"[tls]\nfake-preflight = 1\nfake-seq = \"offset:-10\"\n",
			true,
		},
		{
			"large negative offset",
			"[tls]\nfake-preflight = 1\nfake-seq = \"offset:-10000\"\n",
			false,
		},
		{"positive offset", "[tls]\nfake-preflight = 1\nfake-seq = \"offset:10\"\n", false},
		{"rand", "[tls]\nfake-preflight = 1\nfake-seq = \"rand\"\n", false},
		{"no fakes", "[tls]\nfake-seq = \"offset:-10\"\n", false},
		{"rule with small offset", `
[[rules]]
name = "r"
match = { domains = ["example.com"] }
tls = { fake-preflight = 1, fake-seq = "offset:-10" }
`, true},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			_, warns := runWithTOML(t, tc.toml)
			found := false
			for _, w := range warns {
				if strings.Contains(w, warnPart) {
					found = true
				}
			}
			assert.Equal(t, tc.wantWarn, found, "warnings: %v", warns)
		})
	}
}
