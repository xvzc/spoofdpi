package config

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"
)

func TestCreateCommand_Flags(t *testing.T) {
	tcs := []struct {
		name   string
		args   []string
		assert func(t *testing.T, cfg *Config)
	}{
		{
			name: "default values (no flags)",
			args: []string{"spoofdpi", "--clean"},
			assert: func(t *testing.T, cfg *Config) {
				// Verify defaults are preserved
				assert.Equal(t, zerolog.InfoLevel, cfg.App.LogLevel)
				assert.False(t, cfg.App.NoTUI)
				assert.False(t, cfg.App.AutoConfigureNetwork)
				assert.Equal(t, "127.0.0.1:8080", cfg.App.ListenAddr.String())
				assert.True(t, cfg.App.Gateway.IsZero())
				assert.Equal(t, uint8(8), cfg.Conn.HopCountDefault)
				assert.Equal(t, int64(5000), cfg.DNS.Timeout.Milliseconds())
				assert.Equal(t, int64(10000), cfg.Conn.TCPTimeout.Milliseconds())
				assert.Equal(t, int64(120000), cfg.Conn.UDPIdleTimeout.Milliseconds())
				assert.Equal(t, "8.8.8.8:53", cfg.DNS.Addr.String())
				assert.Equal(t, DNSModeUDP, cfg.DNS.Mode)
				assert.Equal(t, "https://dns.google/dns-query", cfg.DNS.HTTPSURL)
				assert.Equal(t, DNSQueryIPv4, cfg.DNS.QType)
				assert.Equal(t, uint8(0), cfg.HTTPS.FakePreflight)
				assert.False(t, cfg.HTTPS.Disorder)
				assert.Equal(t, HTTPSSplitModeSNI, cfg.HTTPS.SplitMode)
				assert.Equal(t, uint8(35), cfg.HTTPS.ChunkSize)
				assert.False(t, cfg.HTTPS.Skip)
				assert.Equal(t, uint8(0), cfg.UDP.FakePreflight)
				assert.Equal(t, 64, len(cfg.UDP.FakePacket))
			},
		},
		{
			name: "all flags set with custom values",
			args: []string{
				"spoofdpi",
				"--clean", // Ensure no config file interferes
				"--log-level", "debug",
				"--no-tui",
				"--auto-configure-network",
				"--listen-addr", "127.0.0.1:9090",
				"--gateway", "192.168.1.1",
				"--ipv6",
				"--hop-count-default", "128",
				"--dns-timeout", "6000",
				"--tcp-timeout", "5000",
				"--udp-idle-timeout", "5000",
				"--dns-addr", "1.1.1.1:53",
				"--dns-mode", "https",
				"--dns-https-url", "https://cloudflare-dns.com/dns-query",
				"--dns-qtype", "ipv6",
				"--dns-cache",
				"--tls-fake-preflight", "10",
				"--tls-fake-packet", "0x16, 0x03",
				"--tls-disorder",
				"--tls-split-mode", "chunk:50",
				"--tls-skip",
				"--udp-fake-preflight", "5",
				"--udp-fake-packet", "0x01, 0x02",
			},
			assert: func(t *testing.T, cfg *Config) {
				// General
				assert.Equal(t, zerolog.DebugLevel, cfg.App.LogLevel)
				assert.True(t, cfg.App.NoTUI)
				assert.True(t, cfg.App.AutoConfigureNetwork)

				// Server
				assert.Equal(t, "127.0.0.1:9090", cfg.App.ListenAddr.String())
				assert.Equal(t, Gateways{V4: net.IPv4(192, 168, 1, 1).To4()}, cfg.App.Gateway)
				assert.True(t, cfg.App.IPv6)
				assert.Equal(t, uint8(128), cfg.Conn.HopCountDefault)
				assert.Equal(t, 5000*time.Millisecond, cfg.Conn.TCPTimeout)
				assert.Equal(t, 5000*time.Millisecond, cfg.Conn.UDPIdleTimeout)

				// DNS
				assert.Equal(t, "1.1.1.1:53", cfg.DNS.Addr.String())
				assert.Equal(t, DNSModeHTTPS, cfg.DNS.Mode)
				assert.Equal(
					t,
					"https://cloudflare-dns.com/dns-query",
					cfg.DNS.HTTPSURL,
				)
				assert.Equal(t, DNSQueryAll, cfg.DNS.QType, "follows --ipv6")
				assert.Equal(t, 6000*time.Millisecond, cfg.DNS.Timeout)

				// HTTPS
				assert.Equal(t, uint8(10), cfg.HTTPS.FakePreflight)
				assert.Equal(t, []byte{0x16, 0x03}, cfg.HTTPS.FakePacket.Raw())
				assert.True(t, cfg.HTTPS.Disorder)
				assert.Equal(t, HTTPSSplitModeChunk, cfg.HTTPS.SplitMode)
				assert.Equal(t, uint8(50), cfg.HTTPS.ChunkSize)
				assert.True(t, cfg.HTTPS.Skip)

				// UDP
				assert.Equal(t, uint8(5), cfg.UDP.FakePreflight)
				assert.Equal(t, []byte{0x01, 0x02}, cfg.UDP.FakePacket)
			},
		},
		{
			name: "alternative values",
			args: []string{
				"spoofdpi",
				"--clean",
				"--log-level", "error",
				"--dns-mode", "system",
				"--tls-split-mode", "random",
			},
			assert: func(t *testing.T, cfg *Config) {
				assert.Equal(t, zerolog.ErrorLevel, cfg.App.LogLevel)
				assert.Equal(t, DNSModeSystem, cfg.DNS.Mode)
				assert.Equal(t, HTTPSSplitModeRandom, cfg.HTTPS.SplitMode)
			},
		},
		{
			name: "ipv6 listen addr",
			args: []string{
				"spoofdpi",
				"--clean",
				"--listen-addr", "[::1]:1080",
			},
			assert: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "[::1]:1080", cfg.App.ListenAddr.String())
				ip := net.ParseIP("::1")
				assert.True(t, cfg.App.ListenAddr.IP.Equal(ip))
			},
		},
		{
			name: "socks5 default port",
			args: []string{
				"spoofdpi",
				"--clean",
				"--app-mode", "socks5",
			},
			assert: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "127.0.0.1:1080", cfg.App.ListenAddr.String())
				assert.Equal(t, AppModeSOCKS5, cfg.App.Mode)
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			var capturedCfg *Config
			runFunc := func(ctx context.Context, configDir string, cfg *Config) error {
				capturedCfg = cfg
				return nil
			}

			cmd := CreateCommand(runFunc, "v0.0.0", "commit", "build")
			// We need to suppress stdout/stderr for cleaner test output,
			// or we can let it be.
			// cmd.Writer = io.Discard
			// cmd.ErrWriter = io.Discard

			err := cmd.Run(context.Background(), tc.args)
			require.NoError(t, err)
			require.NotNil(t, capturedCfg, "Run function was not called")

			tc.assert(t, capturedCfg)
		})
	}
}

func TestCreateCommand_Gateway(t *testing.T) {
	v4, v6 := net.IPv4(192, 168, 1, 1).To4(), net.ParseIP("fe80::1")
	tcs := []struct {
		name    string
		toml    string
		args    []string
		want    Gateways
		wantErr string
	}{
		{
			name: "repeated flag",
			args: []string{"--gateway", "192.168.1.1", "--gateway", "fe80::1%en0"},
			want: Gateways{V4: v4, V6: v6, V6Zone: "en0"},
		},
		{
			name: "comma-separated",
			args: []string{"--gateway", "fe80::1%en0, 192.168.1.1"},
			want: Gateways{V4: v4, V6: v6, V6Zone: "en0"},
		},
		{
			name: "flag replaces the whole toml value",
			toml: `gateway = ["10.0.0.1", "fe80::1%en0"]`,
			args: []string{"--gateway", "192.168.1.1"},
			want: Gateways{V4: v4},
		},
		{
			name: "empty flag value means automatic discovery",
			toml: `gateway = ["10.0.0.1"]`,
			args: []string{"--gateway", ""},
			want: Gateways{},
		},
		{
			name: "toml array",
			toml: `gateway = ["192.168.1.1", "fe80::1%en0"]`,
			want: Gateways{V4: v4, V6: v6, V6Zone: "en0"},
		},
		{
			name: "empty toml array means automatic discovery",
			toml: `gateway = []`,
			want: Gateways{},
		},
		{
			name:    "two ipv4 gateways",
			args:    []string{"--gateway", "192.168.1.1", "--gateway", "10.0.0.1"},
			wantErr: "more than one IPv4 gateway",
		},
		{
			name:    "zone on a global address",
			args:    []string{"--gateway", "2001:db8::1%en0"},
			wantErr: "only a link-local IPv6 address may have a zone",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "spoofdpi.toml")
			require.NoError(t, os.WriteFile(configPath, []byte("[app]\n"+tc.toml), 0o644))

			var capturedCfg *Config
			runFunc := func(ctx context.Context, configDir string, cfg *Config) error {
				capturedCfg = cfg
				return nil
			}
			cmd := CreateCommand(runFunc, "v0.0.0", "commit", "build")
			args := append([]string{"spoofdpi", "--config", configPath}, tc.args...)

			err := cmd.Run(context.Background(), args)
			if tc.wantErr != "" {
				assert.ErrorContains(t, err, tc.wantErr)
				assert.Nil(t, capturedCfg)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, capturedCfg)
			assert.Equal(t, tc.want, capturedCfg.App.Gateway)
		})
	}
}

func TestCreateCommand_ConnTimeoutRange(t *testing.T) {
	tcs := []struct {
		value   string
		want    time.Duration
		wantErr string
	}{
		{value: "0", wantErr: "value 0 out of range[1-3600000]"},
		{value: "1", want: time.Millisecond},
		{value: "120000", want: 2 * time.Minute},
		{value: "3600000", want: time.Hour},
		{value: "3600001", wantErr: "value 3600001 out of range[1-3600000]"},
	}
	flags := map[string]func(*Config) time.Duration{
		"--tcp-timeout":      func(c *Config) time.Duration { return c.Conn.TCPTimeout },
		"--udp-idle-timeout": func(c *Config) time.Duration { return c.Conn.UDPIdleTimeout },
	}
	for flag, get := range flags {
		for _, tc := range tcs {
			t.Run(flag+"="+tc.value, func(t *testing.T) {
				var got *Config
				runFunc := func(ctx context.Context, configDir string, cfg *Config) error {
					got = cfg
					return nil
				}

				cmd := CreateCommand(runFunc, "v0.0.0", "commit", "build")
				err := cmd.Run(
					context.Background(),
					[]string{"spoofdpi", "--clean", flag, tc.value},
				)
				if tc.wantErr != "" {
					assert.ErrorContains(t, err, tc.wantErr)
					assert.Nil(t, got)
					return
				}
				require.NoError(t, err)
				require.NotNil(t, got)
				assert.Equal(t, tc.want, get(got))
			})
		}
	}
}

func TestCreateCommand_OverrideTOML(t *testing.T) {
	tomlContent := `
[app]
    log-level = "debug"
    silent = true
    system-proxy = true

[connection]
    listen-addr = "127.0.0.1:8080"
    tcp-timeout = 1000
    udp-idle-timeout = 1000
    hop-count-default = 100

[dns]
    addr = "8.8.8.8:53"
    cache = true
    mode = "https"
    https-url = "https://1.1.1.1/dns-query"
    qtype = "ipv4"
    timeout = 1000

[tls]
    disorder = true
    fake-preflight = 5
    fake-packet = [0x01, 0x02, 0x03]
    split-mode = "chunk:20"
    skip = true

[[rules]]
    name = "test-rule"
    priority = 100
    block = true
    match = {
        domains = ["example.com"],
        cidrs = ["192.168.1.0/24"],
    }
    dns = {
        mode = "udp",
        addr = "8.8.4.4:53",
        https-url = "https://8.8.8.8/dns-query",
        qtype = "ipv6",
        block = true,
        cache = false,
    }
    tls = {
        disorder = false,
        fake-preflight = 2,
        fake-packet = [0xAA, 0xBB],
        split-mode = "chunk:10",
        skip = true,
    }
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "spoofdpi.toml")
	err := os.WriteFile(configPath, []byte(tomlContent), 0o644)
	require.NoError(t, err)

	var capturedCfg *Config
	runFunc := func(ctx context.Context, configDir string, cfg *Config) error {
		capturedCfg = cfg
		return nil
	}

	cmd := CreateCommand(runFunc, "v0.0.0", "commit", "build")

	args := []string{
		"spoofdpi",
		"--config", configPath,
		"--log-level", "error",
		"--no-tui=false",
		"--auto-configure-network=false",
		"--listen-addr", "127.0.0.1:9090",
		"--dns-timeout", "2000",
		"--tcp-timeout", "2000",
		"--udp-idle-timeout", "2000",
		"--hop-count-default", "200",
		"--dns-addr", "1.1.1.1:53",
		"--dns-cache=false",
		"--dns-mode", "udp",
		"--dns-https-url", "https://8.8.8.8/dns-query",
		"--dns-qtype", "ipv6",
		"--tls-disorder=false",
		"--tls-fake-preflight", "10",
		"--tls-fake-packet", "0xff,0xff",
		"--tls-split-mode", "chunk:10",
		"--tls-skip=false",
		"--udp-fake-preflight", "20",
		"--udp-fake-packet", "0xcc,0xdd",
	}

	err = cmd.Run(context.Background(), args)
	require.NoError(t, err)
	require.NotNil(t, capturedCfg)

	// Verify Overrides
	// General
	assert.Equal(t, zerolog.ErrorLevel, capturedCfg.App.LogLevel)
	assert.False(t, capturedCfg.App.NoTUI)
	assert.False(t, capturedCfg.App.AutoConfigureNetwork)

	// Server
	assert.Equal(t, "127.0.0.1:9090", capturedCfg.App.ListenAddr.String())
	assert.Equal(t, 2000*time.Millisecond, capturedCfg.DNS.Timeout)
	assert.Equal(t, 2000*time.Millisecond, capturedCfg.Conn.TCPTimeout)
	assert.Equal(t, 2000*time.Millisecond, capturedCfg.Conn.UDPIdleTimeout)
	assert.Equal(t, uint8(200), capturedCfg.Conn.HopCountDefault)

	// DNS
	assert.Equal(t, "1.1.1.1:53", capturedCfg.DNS.Addr.String())
	assert.Equal(t, DNSModeUDP, capturedCfg.DNS.Mode)
	assert.Equal(t, "https://8.8.8.8/dns-query", capturedCfg.DNS.HTTPSURL)

	// HTTPS
	assert.False(t, capturedCfg.HTTPS.Disorder)
	assert.Equal(t, uint8(10), capturedCfg.HTTPS.FakePreflight)
	assert.Equal(t, []byte{0xff, 0xff}, capturedCfg.HTTPS.FakePacket.Raw())
	assert.Equal(t, HTTPSSplitModeChunk, capturedCfg.HTTPS.SplitMode)
	assert.Equal(t, uint8(10), capturedCfg.HTTPS.ChunkSize)
	assert.False(t, capturedCfg.HTTPS.Skip)

	// UDP
	assert.Equal(t, uint8(20), capturedCfg.UDP.FakePreflight)
	assert.Equal(t, []byte{0xcc, 0xdd}, capturedCfg.UDP.FakePacket)
	assert.Equal(t, []byte{0xcc, 0xdd}, capturedCfg.UDP.FakePacket)

	// Verify TOML-only fields are preserved
	require.Len(t, capturedCfg.Rules, 1)
	rule := capturedCfg.Rules[0]
	assert.Equal(t, "test-rule", rule.Name)
	assert.Equal(t, "example.com", rule.Match.Domains[0])
}

// TestLoad_RuleInheritsFromCLIAndTOML pins the end-to-end precedence
// for fields a rule leaves unset:
// rule-set > CLI > TOML > package default. The two halves of the
// pipeline (CLI-over-TOML at base, rule-over-base) are covered
// individually by TestCreateCommand_OverrideTOML and
// TestResolveRules_inheritsFromBase, but their composition wasn't —
// so a regression that broke base→rule plumbing could slip through.
func TestLoad_RuleInheritsFromCLIAndTOML(t *testing.T) {
	tomlContent := `
[tls]
    split-mode = "chunk:20"
    syn-ack-timeout = 50

[[rules]]
    name = "partial-rule"
    match = { domains = ["example.com"] }
    tls = { split-mode = "chunk:50", skip = true }
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "spoofdpi.toml")
	require.NoError(t, os.WriteFile(configPath, []byte(tomlContent), 0o644))

	var capturedCfg *Config
	cmd := CreateCommand(
		func(_ context.Context, _ string, cfg *Config) error {
			capturedCfg = cfg
			return nil
		},
		"v0.0.0", "commit", "build",
	)

	args := []string{
		"spoofdpi",
		"--config", configPath,
		// CLI sets a key the TOML and the rule both leave alone:
		"--tls-fake-preflight", "10",
	}
	require.NoError(t, cmd.Run(context.Background(), args))
	require.NotNil(t, capturedCfg)
	require.Len(t, capturedCfg.Rules, 1)

	rule := capturedCfg.Rules[0]

	// Override-set wins
	assert.Equal(
		t,
		uint8(50),
		rule.Config.HTTPS.ChunkSize,
		"rule overrides the chunk size",
	)
	assert.True(t, rule.Config.HTTPS.Skip, "rule sets skip explicitly")

	// TOML inherited (rule didn't set, CLI didn't touch)
	assert.Equal(t, 50*time.Millisecond, rule.Config.HTTPS.SynAckTimeout,
		"rule inherits syn-ack-timeout from static TOML")

	// CLI inherited (rule didn't set, TOML didn't set) — the key claim
	assert.Equal(t, uint8(10), rule.Config.HTTPS.FakePreflight,
		"rule inherits fake-preflight from CLI override")

	// Package default inherited (no one set it)
	assert.False(t, rule.Config.HTTPS.Disorder,
		"rule inherits disorder=false from package default")
}

// TestCreateCommand_EnumUsageMatchesValidator guards the enum flags' help text
// against drifting away from the values their validators actually accept.
// Regression test: --dns-mode advertised <'udp'|'doh'|'sys'> while only
// "udp", "https" and "system" were accepted, and --tls-split-mode (then
// --https-split-mode) listed
// "sni" twice while omitting "first-byte".
func TestCreateCommand_EnumUsageMatchesValidator(t *testing.T) {
	tcs := []struct {
		flag   string
		values []string
	}{
		{flag: "app-mode", values: availableAppModeValues},
		{flag: "dns-mode", values: availableDNSModeValues},
		{flag: "tls-split-mode", values: availableHTTPSModeValues},
	}

	runFunc := func(ctx context.Context, configDir string, cfg *Config) error {
		return nil
	}
	cmd := CreateCommand(runFunc, "v0.0.0", "commit", "build")

	usageOf := func(t *testing.T, name string) string {
		t.Helper()
		for _, f := range cmd.Flags {
			if !slices.Contains(f.Names(), name) {
				continue
			}
			df, ok := f.(cli.DocGenerationFlag)
			require.True(t, ok, "flag --%s does not expose its usage", name)
			return df.GetUsage()
		}
		t.Fatalf("flag --%s not found", name)
		return ""
	}

	for _, tc := range tcs {
		t.Run(tc.flag, func(t *testing.T) {
			// The hint must list every accepted value, exactly once each,
			// and advertise nothing the validator would reject.
			assert.Contains(t, usageOf(t, tc.flag), enumUsage(tc.values))
		})
	}
}

// TestEnumUsage pins the rendering of the usage hint.
func TestEnumUsage(t *testing.T) {
	assert.Equal(
		t,
		`<"udp"|"https"|"system">`,
		enumUsage([]string{"udp", "https", "system"}),
	)
	assert.Equal(t, `<"only">`, enumUsage([]string{"only"}))
}
