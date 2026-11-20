package livetest

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runCommand runs the livetest command with args after the command name.
func runCommand(
	t *testing.T,
	executable func() (string, error),
	args ...string,
) (stdout, stderr string, err error) {
	t.Helper()
	var outBuf, errBuf bytes.Buffer
	cmd := newCommand(executable, testCaseFlags, &errBuf)
	cmd.Writer = &outBuf
	err = cmd.Run(context.Background(), append([]string{"spoofdpi livetest"}, args...))
	return outBuf.String(), errBuf.String(), err
}

func binary(path string) func() (string, error) {
	return func() (string, error) { return path, nil }
}

func TestCommand_Run(t *testing.T) {
	bin := fakeSpoofdpi(t, "WRN config file not found")
	outDir := filepath.Join(t.TempDir(), "logs")

	stdout, stderr, err := runCommand(t, binary(bin),
		"--listen", fakeProxy(t, DefaultUserAgent),
		"--url", "http://ok.test/",
		"--tries", "1",
		"--add", "label:pkt, --tls-fake-packet 0x16,0x03",
		"--add", "--tls-disorder",
		"--out", outDir,
	)
	require.NoError(t, err, stderr)

	assert.Contains(t, stdout, "baseline config: none (defaults)")
	assert.Contains(t, stdout, "1/1")
	assert.Contains(t, readLog(t, outDir, "pkt"), "--clean --tls-fake-packet 0x16,0x03")
	assert.Contains(t, readLog(t, outDir, "add-2"), "--clean --tls-disorder")
}

func TestCommand_UserAgent(t *testing.T) {
	bin := fakeSpoofdpi(t, "WRN config file not found")
	stdout, stderr, err := runCommand(t, binary(bin),
		"--listen", fakeProxy(t, "foo"),
		"--url", "http://ok.test/",
		"--tries", "1",
		"--user-agent", "foo",
	)
	require.NoError(t, err, stderr)
	assert.Contains(t, stdout, "1/1")
}

func TestCommand_IgnoredFlagExitsZero(t *testing.T) {
	bin := fakeSpoofdpi(t, "WRN config file not found")
	_, stderr, err := runCommand(t, binary(bin),
		"--listen", fakeProxy(t, DefaultUserAgent),
		"--url", "http://ok.test/",
		"--tries", "1",
		"--no-baseline",
		"--add", "--app-mode socks5 --tls-disorder",
	)
	require.NoError(t, err, stderr)
	assert.Contains(
		t,
		stderr,
		`livetest: case "add-1": ignored --app-mode socks5 (set by livetest)`,
	)
	assert.NotContains(t, stderr, "--app-mode socks5 --tls-disorder")
	assert.Contains(t, stderr, "--auto-configure-network=false --clean --tls-disorder\n")
}

func TestCommand_FailedCaseExitsZero(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "spoofdpi")
	require.NoError(t, os.WriteFile(bin, []byte("#!/bin/sh\nexit 1\n"), 0o755))

	_, stderr, err := runCommand(t, binary(bin), "--url", "http://ok.test/")
	assert.NoError(t, err)
	assert.Contains(t, stderr, "exited before starting")
}

func TestCommand_UsageErrors(t *testing.T) {
	notRun := func() (string, error) {
		t.Error("executable looked up after a flag error")
		return "", errors.New("unreachable")
	}
	tcs := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{name: "no url", args: nil, wantErr: "--url"},
		{
			name:    "server flag",
			args:    []string{"--url", "http://a/", "--tls-fake-stutter", "1"},
			wantErr: "flag provided but not defined: -tls-fake-stutter",
		},
		{
			name:    "log level is not a livetest flag",
			args:    []string{"--url", "http://a/", "--log-level", "info"},
			wantErr: "flag provided but not defined: -log-level",
		},
		{
			name:    "url without a scheme",
			args:    []string{"--url", "example.com"},
			wantErr: `invalid value "example.com" for flag -url: "example.com": scheme must be http or https`,
		},
		{
			name:    "url with another scheme",
			args:    []string{"--url", "ftp://a/"},
			wantErr: "scheme must be http or https",
		},
		{
			name:    "url without a host",
			args:    []string{"--url", "http:///path"},
			wantErr: "host is missing",
		},
		{
			name:    "listen without a port",
			args:    []string{"--url", "http://a/", "--listen", "foo"},
			wantErr: `invalid value "foo" for flag -listen:`,
		},
		{
			name:    "listen with a host name",
			args:    []string{"--url", "http://a/", "--listen", "localhost:1"},
			wantErr: "is not an IP address",
		},
		{
			name:    "listen with a bad port",
			args:    []string{"--url", "http://a/", "--listen", "127.0.0.1:70000"},
			wantErr: "is not a port number",
		},
		{
			name:    "missing config",
			args:    []string{"--url", "http://a/", "--config", "/nonexistent/spoofdpi.toml"},
			wantErr: "for flag -config: stat /nonexistent/spoofdpi.toml: no such file",
		},
		{
			name:    "config is a directory",
			args:    []string{"--url", "http://a/", "--config", os.TempDir()},
			wantErr: "not a regular file",
		},
		{
			name:    "empty user agent",
			args:    []string{"--url", "http://a/", "--user-agent", ""},
			wantErr: "--user-agent must not be empty",
		},
		{
			name:    "no baseline and no add",
			args:    []string{"--url", "http://a/", "--no-baseline"},
			wantErr: "--no-baseline",
		},
		{
			name:    "bad tries",
			args:    []string{"--url", "http://a/", "--tries", "0"},
			wantErr: "--tries",
		},
		{
			name:    "bad mode",
			args:    []string{"--url", "http://a/", "--mode", "tun"},
			wantErr: "--mode",
		},
		{
			name:    "bad timeout",
			args:    []string{"--url", "http://a/", "--timeout", "0s"},
			wantErr: "--timeout",
		},
		{
			name:    "extra argument",
			args:    []string{"--url", "http://a/", "extra"},
			wantErr: "unexpected arguments",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			executable := binary("/nonexistent/spoofdpi")
			if strings.Contains(tc.wantErr, "not defined") {
				executable = notRun
			}
			_, _, err := runCommand(t, executable, tc.args...)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestCommand_ExecutableError(t *testing.T) {
	_, _, err := runCommand(t,
		func() (string, error) { return "", errors.New("no such file") },
		"--url", "http://a/",
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "find the spoofdpi executable: no such file")
}

func TestCommand_Help(t *testing.T) {
	stdout, _, err := runCommand(t, binary("/nonexistent"), "--help")
	require.NoError(t, err)

	assert.Contains(t, stdout, "livetest [options]")
	for _, flag := range []string{
		"--add", "--url", "--tries", "--timeout", "--start-timeout", "--mode",
		"--listen", "--config", "--user-agent", "--out", "--no-baseline", "--help,",
	} {
		assert.Contains(t, stdout, flag+" ")
	}
	assert.Contains(t, stdout, `(default: "`+DefaultUserAgent+`")`)
	assert.NotContains(t, stdout, "--log-level")
	for _, flag := range []string{"--tls-", "--app-mode", "--listen-addr", "--no-tui"} {
		assert.NotContains(t, stdout, flag)
	}
}
