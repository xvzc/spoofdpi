package config

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"
)

func writeTOML(t *testing.T, dir, content string) string {
	t.Helper()
	p := filepath.Join(dir, "spoofdpi.toml")
	require.NoError(t, os.WriteFile(p, []byte(content), 0o644))
	return p
}

func TestLoadDNS_explicitPathDecodesOnlyDNS(t *testing.T) {
	// The [tls] and [[rules]] values are invalid; LoadDNS must not
	// look at them.
	p := writeTOML(t, t.TempDir(), `
[connection]
    tcp-timeout = "not a number"

[dns]
    mode = "https"
    https-url = "https://1.1.1.1/dns-query"
    timeout = 1500

[tls]
    split-mode = "bogus"

[[rules]]
    priority = -1
    match = { domains = ["bad domain!"] }
`)

	opts, used, err := LoadDNS(p)
	require.NoError(t, err)
	assert.Equal(t, p, used)

	want := DefaultConfig().DNS
	want.Mode = DNSModeHTTPS
	want.HTTPSURL = "https://1.1.1.1/dns-query"
	want.Timeout = 1500 * time.Millisecond
	assert.Equal(t, want, opts)
}

func TestLoadDNS_noDNSSectionKeepsDefaults(t *testing.T) {
	p := writeTOML(t, t.TempDir(), `
[app]
    mode = "socks5"
`)

	opts, used, err := LoadDNS(p)
	require.NoError(t, err)
	assert.Equal(t, p, used)
	assert.Equal(t, DefaultConfig().DNS, opts)
}

func TestLoadDNS_invalidDNSValueIsError(t *testing.T) {
	tcs := []struct {
		name    string
		content string
	}{
		{"bad mode", "[dns]\nmode = \"tcp\"\n"},
		{"bad addr", "[dns]\naddr = \"nope\"\n"},
		{"timeout out of range", "[dns]\ntimeout = 70000\n"},
		{"timeout zero", "[dns]\ntimeout = 0\n"},
		{"dns not a table", "dns = 1\n"},
		{"toml syntax error", "[dns\n"},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			p := writeTOML(t, t.TempDir(), tc.content)
			_, _, err := LoadDNS(p)
			require.Error(t, err)
			assert.Contains(t, err.Error(), p)
		})
	}
}

func TestLoadDNS_missingExplicitPathIsError(t *testing.T) {
	_, _, err := LoadDNS(filepath.Join(t.TempDir(), "missing.toml"))
	assert.Error(t, err)
}

func TestLoadDNS_searchesDefaultLocations(t *testing.T) {
	if _, err := os.Stat("/etc/spoofdpi.toml"); err == nil {
		t.Skip("/etc/spoofdpi.toml exists and takes precedence")
	}

	xdg := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(xdg, "spoofdpi"), 0o755))
	p := writeTOML(t, filepath.Join(xdg, "spoofdpi"), "[dns]\nmode = \"system\"\n")
	t.Setenv("XDG_CONFIG_HOME", xdg)

	opts, used, err := LoadDNS("")
	require.NoError(t, err)
	assert.Equal(t, p, used)
	assert.Equal(t, DNSModeSystem, opts.Mode)
}

func TestResolveRules_dnsTimeout(t *testing.T) {
	base := DefaultConfig().RuntimeConfig
	base.DNS.Timeout = 2000 * time.Millisecond

	raw := []map[string]any{
		{"dns": map[string]any{"timeout": int64(1500)}},
		{"dns": map[string]any{"mode": "https"}},
	}

	rules, err := resolveRules(raw, base)
	require.NoError(t, err)
	require.Len(t, rules, 2)
	assert.Equal(t, 1500*time.Millisecond, rules[0].Config.DNS.Timeout)
	assert.Equal(
		t, 2000*time.Millisecond, rules[1].Config.DNS.Timeout,
		"rule inherits the timeout from base",
	)
}

func TestResolveRules_connTimeoutRange(t *testing.T) {
	tcs := []struct {
		value   int64
		want    time.Duration
		wantErr string
	}{
		{value: 0, wantErr: "value 0 out of range[1-3600000]"},
		{value: 1, want: time.Millisecond},
		{value: 120000, want: 2 * time.Minute},
		{value: 3600000, want: time.Hour},
		{value: 3600001, wantErr: "value 3600001 out of range[1-3600000]"},
	}
	keys := map[string]func(RuntimeConfig) time.Duration{
		"tcp-timeout":      func(c RuntimeConfig) time.Duration { return c.Conn.TCPTimeout },
		"udp-idle-timeout": func(c RuntimeConfig) time.Duration { return c.Conn.UDPIdleTimeout },
	}
	for key, get := range keys {
		for _, tc := range tcs {
			t.Run(fmt.Sprintf("%s=%d", key, tc.value), func(t *testing.T) {
				raw := []map[string]any{
					{"connection": map[string]any{key: tc.value}},
				}

				rules, err := resolveRules(raw, DefaultConfig().RuntimeConfig)
				if tc.wantErr != "" {
					assert.ErrorContains(t, err, tc.wantErr)
					return
				}
				require.NoError(t, err)
				require.Len(t, rules, 1)
				assert.Equal(t, tc.want, get(rules[0].Config))
			})
		}
	}
}

func TestDNSFlags(t *testing.T) {
	run := func(args ...string) (DNSOptions, error) {
		opts := DefaultConfig().DNS
		var overrides []func(*DNSOptions)
		cmd := &cli.Command{
			Name: "test",
			Flags: DNSFlags(func(apply func(*DNSOptions)) {
				overrides = append(overrides, apply)
			}),
		}
		err := cmd.Run(context.Background(), append([]string{"test"}, args...))
		for _, apply := range overrides {
			apply(&opts)
		}
		return opts, err
	}

	t.Run("unset flags leave the options alone", func(t *testing.T) {
		opts, err := run()
		require.NoError(t, err)
		assert.Equal(t, DefaultConfig().DNS, opts)
	})

	t.Run("set flags override", func(t *testing.T) {
		opts, err := run(
			"--dns-addr", "1.1.1.1:53",
			"--dns-mode", "https",
			"--dns-https-url", "https://1.1.1.1/dns-query",
			"--dns-timeout", "1",
		)
		require.NoError(t, err)
		assert.Equal(t, "1.1.1.1:53", opts.Addr.String())
		assert.Equal(t, DNSModeHTTPS, opts.Mode)
		assert.Equal(t, "https://1.1.1.1/dns-query", opts.HTTPSURL)
		assert.Equal(t, time.Millisecond, opts.Timeout)
	})

	for _, args := range [][]string{
		{"--dns-addr", "nope"},
		{"--dns-mode", "tcp"},
		{"--dns-https-url", "ftp://x"},
		{"--dns-timeout", "70000"},
		{"--dns-timeout", "0"},
	} {
		t.Run("rejects "+args[0]+" "+args[1], func(t *testing.T) {
			_, err := run(args...)
			assert.Error(t, err)
		})
	}
}
