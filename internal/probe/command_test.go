package probe

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runCommand runs the probe command with args after the command name.
func runCommand(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var outBuf, errBuf bytes.Buffer
	cmd := newCommand(&errBuf)
	cmd.Writer = &outBuf
	err = cmd.Run(context.Background(), append([]string{"spoofdpi probe"}, args...))
	return outBuf.String(), errBuf.String(), err
}

func TestCommand_Help(t *testing.T) {
	out, _, err := runCommand(t, "--help")
	require.NoError(t, err)
	assert.Contains(
		t,
		out,
		"NAME:\n  probe - Measure hop counts and DPI behavior of sites\n",
	)
	assert.Contains(t, out, "USAGE:\n  probe [options]\n")
	for _, flag := range []string{
		"--url", "--max-ttl", "--timeout", "--config", "--clean",
		"--dns-addr", "--dns-mode", "--dns-https-url", "--dns-timeout",
	} {
		assert.Contains(t, out, "  "+flag+" ")
	}
	assert.NotContains(t, out, "--dns-qtype")
	assert.NotContains(t, out, "--tries")
	assert.NotContains(t, out, `(default: "udp") (default: "udp")`)
}

func TestCommand_UsageErrors(t *testing.T) {
	t.Setenv("SPOOFDPI_CONFIG", "")
	tcs := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "no url",
			args:    []string{"--clean"},
			wantErr: "at least one --url is required",
		},
		{
			name:    "stray argument",
			args:    []string{"--clean", "--url", "a.test", "b.test"},
			wantErr: `unexpected arguments: ["b.test"]`,
		},
		{
			name:    "scheme",
			args:    []string{"--url", "https://a.test"},
			wantErr: `invalid value "https://a.test" for flag -url: "https://a.test": give the host only, without a scheme`,
		},
		{
			name:    "port",
			args:    []string{"--url", "a.test:443"},
			wantErr: `invalid value "a.test:443" for flag -url: "a.test:443": give the host only, without a port (443 is used)`,
		},
		{
			name:    "max-ttl 0",
			args:    []string{"--clean", "--url", "a.test", "--max-ttl", "0"},
			wantErr: "--max-ttl must be from 1 to 255",
		},
		{
			name:    "max-ttl 256",
			args:    []string{"--clean", "--url", "a.test", "--max-ttl", "256"},
			wantErr: "--max-ttl must be from 1 to 255",
		},
		{
			name:    "tries is not a probe flag",
			args:    []string{"--clean", "--url", "a.test", "--tries", "2"},
			wantErr: "flag provided but not defined: -tries",
		},
		{
			name:    "timeout 0",
			args:    []string{"--clean", "--url", "a.test", "--timeout", "0s"},
			wantErr: "--timeout must be positive",
		},
		{
			name:    "max-ttl twice",
			args:    []string{"--url", "a.test", "--max-ttl", "8", "--max-ttl", "9"},
			wantErr: "max-ttl",
		},
		{
			name:    "qtype is not a probe flag",
			args:    []string{"--url", "a.test", "--dns-qtype", "ipv6"},
			wantErr: "flag provided but not defined: -dns-qtype",
		},
		{
			name:    "server flag",
			args:    []string{"--url", "a.test", "--tls-fake-stutter", "1"},
			wantErr: "flag provided but not defined: -tls-fake-stutter",
		},
		{
			name:    "bad dns mode",
			args:    []string{"--url", "a.test", "--dns-mode", "carrier-pigeon"},
			wantErr: "dns-mode",
		},
		{
			name:    "missing config",
			args:    []string{"--url", "a.test", "--config", "/nonexistent/spoofdpi.toml"},
			wantErr: "no such file: /nonexistent/spoofdpi.toml",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			stdout, _, err := runCommand(t, tc.args...)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
			assert.Empty(t, stdout)
		})
	}
}

func TestCommand_ConfigFromEnv(t *testing.T) {
	t.Setenv("SPOOFDPI_CONFIG", "/nonexistent/spoofdpi.toml")
	_, _, err := runCommand(t, "--url", "a.test")
	assert.EqualError(t, err, "no such file: /nonexistent/spoofdpi.toml")

	// --clean ignores it; the run then stops at the invalid --max-ttl.
	_, _, err = runCommand(t, "--clean", "--url", "a.test", "--max-ttl", "0")
	assert.EqualError(t, err, "--max-ttl must be from 1 to 255")
}

func TestCommand_CommaInURL(t *testing.T) {
	_, _, err := runCommand(t, "--clean", "--url", "a.test,b.test", "--max-ttl", "0")
	assert.EqualError(t, err, "--max-ttl must be from 1 to 255", "the URL is not split")
}
