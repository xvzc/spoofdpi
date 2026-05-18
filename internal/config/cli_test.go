package config

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
				assert.Equal(t, zerolog.InfoLevel, cfg.Startup.App.LogLevel)
				assert.False(t, cfg.Startup.App.NoTUI)
				assert.False(t, cfg.Startup.App.AutoConfigureNetwork)
				assert.Equal(t, "127.0.0.1:8080", cfg.Startup.App.ListenAddr.String())
				assert.Equal(t, uint8(8), cfg.Runtime.Conn.DefaultFakeTTL)
				assert.Equal(t, int64(5000), cfg.Runtime.Conn.DNSTimeout.Milliseconds())
				assert.Equal(t, int64(10000), cfg.Runtime.Conn.TCPTimeout.Milliseconds())
				assert.Equal(t, int64(25000), cfg.Runtime.Conn.UDPIdleTimeout.Milliseconds())
				assert.Equal(t, "8.8.8.8:53", cfg.Runtime.DNS.Addr.String())
				assert.Equal(t, DNSModeUDP, cfg.Runtime.DNS.Mode)
				assert.Equal(t, "https://dns.google/dns-query", cfg.Runtime.DNS.HTTPSURL)
				assert.Equal(t, DNSQueryIPv4, cfg.Runtime.DNS.QType)
				assert.False(t, cfg.Runtime.DNS.Cache)
				assert.Equal(t, uint8(0), cfg.Runtime.HTTPS.FakeCount)
				assert.False(t, cfg.Runtime.HTTPS.Disorder)
				assert.Equal(t, HTTPSSplitModeSNI, cfg.Runtime.HTTPS.SplitMode)
				assert.Equal(t, uint8(35), cfg.Runtime.HTTPS.ChunkSize)
				assert.False(t, cfg.Runtime.HTTPS.Skip)
				assert.Equal(t, uint8(0), cfg.Runtime.UDP.FakeCount)
				assert.Equal(t, 64, len(cfg.Runtime.UDP.FakePacket))
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
				"--default-fake-ttl", "128",
				"--dns-timeout", "5000",
				"--tcp-timeout", "5000",
				"--udp-idle-timeout", "5000",
				"--dns-addr", "1.1.1.1:53",
				"--dns-mode", "https",
				"--dns-https-url", "https://cloudflare-dns.com/dns-query",
				"--dns-qtype", "ipv6",
				"--dns-cache",
				"--https-fake-count", "10",
				"--https-fake-packet", "0x16, 0x03",
				"--https-disorder",
				"--https-split-mode", "chunk",
				"--https-chunk-size", "50",
				"--https-skip",
				"--udp-fake-count", "5",
				"--udp-fake-packet", "0x01, 0x02",
			},
			assert: func(t *testing.T, cfg *Config) {
				// General
				assert.Equal(t, zerolog.DebugLevel, cfg.Startup.App.LogLevel)
				assert.True(t, cfg.Startup.App.NoTUI)
				assert.True(t, cfg.Startup.App.AutoConfigureNetwork)

				// Server
				assert.Equal(t, "127.0.0.1:9090", cfg.Startup.App.ListenAddr.String())
				assert.Equal(t, uint8(128), cfg.Runtime.Conn.DefaultFakeTTL)
				assert.Equal(t, 5000*time.Millisecond, cfg.Runtime.Conn.DNSTimeout)
				assert.Equal(t, 5000*time.Millisecond, cfg.Runtime.Conn.TCPTimeout)
				assert.Equal(t, 5000*time.Millisecond, cfg.Runtime.Conn.UDPIdleTimeout)

				// DNS
				assert.Equal(t, "1.1.1.1:53", cfg.Runtime.DNS.Addr.String())
				assert.Equal(t, DNSModeHTTPS, cfg.Runtime.DNS.Mode)
				assert.Equal(
					t,
					"https://cloudflare-dns.com/dns-query",
					cfg.Runtime.DNS.HTTPSURL,
				)
				assert.Equal(t, DNSQueryIPv6, cfg.Runtime.DNS.QType)
				assert.True(t, cfg.Runtime.DNS.Cache)

				// HTTPS
				assert.Equal(t, uint8(10), cfg.Runtime.HTTPS.FakeCount)
				assert.Equal(t, []byte{0x16, 0x03}, cfg.Runtime.HTTPS.FakePacket.Raw())
				assert.True(t, cfg.Runtime.HTTPS.Disorder)
				assert.Equal(t, HTTPSSplitModeChunk, cfg.Runtime.HTTPS.SplitMode)
				assert.Equal(t, uint8(50), cfg.Runtime.HTTPS.ChunkSize)
				assert.True(t, cfg.Runtime.HTTPS.Skip)

				// UDP
				assert.Equal(t, uint8(5), cfg.Runtime.UDP.FakeCount)
				assert.Equal(t, []byte{0x01, 0x02}, cfg.Runtime.UDP.FakePacket)
			},
		},
		{
			name: "alternative values",
			args: []string{
				"spoofdpi",
				"--clean",
				"--log-level", "error",
				"--dns-mode", "system",
				"--dns-qtype", "all",
				"--https-split-mode", "random",
			},
			assert: func(t *testing.T, cfg *Config) {
				assert.Equal(t, zerolog.ErrorLevel, cfg.Startup.App.LogLevel)
				assert.Equal(t, DNSModeSystem, cfg.Runtime.DNS.Mode)
				assert.Equal(t, DNSQueryAll, cfg.Runtime.DNS.QType)
				assert.Equal(t, HTTPSSplitModeRandom, cfg.Runtime.HTTPS.SplitMode)
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
				assert.Equal(t, "[::1]:1080", cfg.Startup.App.ListenAddr.String())
				ip := net.ParseIP("::1")
				assert.True(t, cfg.Startup.App.ListenAddr.IP.Equal(ip))
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
				assert.Equal(t, "127.0.0.1:1080", cfg.Startup.App.ListenAddr.String())
				assert.Equal(t, AppModeSOCKS5, cfg.Startup.App.Mode)
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

func TestCreateCommand_OverrideTOML(t *testing.T) {
	tomlContent := `
[app]
    log-level = "debug"
    silent = true
    system-proxy = true

[connection]
    listen-addr = "127.0.0.1:8080"
    dns-timeout = 1000
    tcp-timeout = 1000
    udp-idle-timeout = 1000
    default-fake-ttl = 100

[dns]
    addr = "8.8.8.8:53"
    cache = true
    mode = "https"
    https-url = "https://1.1.1.1/dns-query"
    qtype = "ipv4"

[https]
    disorder = true
    fake-count = 5
    fake-packet = [0x01, 0x02, 0x03]
    split-mode = "chunk"
    chunk-size = 20
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
    https = {
        disorder = false,
        fake-count = 2,
        fake-packet = [0xAA, 0xBB],
        split-mode = "sni",
        chunk-size = 10,
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
		"--default-fake-ttl", "200",
		"--dns-addr", "1.1.1.1:53",
		"--dns-cache=false",
		"--dns-mode", "udp",
		"--dns-https-url", "https://8.8.8.8/dns-query",
		"--dns-qtype", "ipv6",
		"--https-disorder=false",
		"--https-fake-count", "10",
		"--https-fake-packet", "0xff,0xff",
		"--https-split-mode", "sni",
		"--https-chunk-size", "10",
		"--https-skip=false",
		"--udp-fake-count", "20",
		"--udp-fake-packet", "0xcc,0xdd",
	}

	err = cmd.Run(context.Background(), args)
	require.NoError(t, err)
	require.NotNil(t, capturedCfg)

	// Verify Overrides
	// General
	assert.Equal(t, zerolog.ErrorLevel, capturedCfg.Startup.App.LogLevel)
	assert.False(t, capturedCfg.Startup.App.NoTUI)
	assert.False(t, capturedCfg.Startup.App.AutoConfigureNetwork)

	// Server
	assert.Equal(t, "127.0.0.1:9090", capturedCfg.Startup.App.ListenAddr.String())
	assert.Equal(t, 2000*time.Millisecond, capturedCfg.Runtime.Conn.DNSTimeout)
	assert.Equal(t, 2000*time.Millisecond, capturedCfg.Runtime.Conn.TCPTimeout)
	assert.Equal(t, 2000*time.Millisecond, capturedCfg.Runtime.Conn.UDPIdleTimeout)
	assert.Equal(t, uint8(200), capturedCfg.Runtime.Conn.DefaultFakeTTL)

	// DNS
	assert.Equal(t, "1.1.1.1:53", capturedCfg.Runtime.DNS.Addr.String())
	assert.False(t, capturedCfg.Runtime.DNS.Cache)
	assert.Equal(t, DNSModeUDP, capturedCfg.Runtime.DNS.Mode)
	assert.Equal(t, "https://8.8.8.8/dns-query", capturedCfg.Runtime.DNS.HTTPSURL)
	assert.Equal(t, DNSQueryIPv6, capturedCfg.Runtime.DNS.QType)

	// HTTPS
	assert.False(t, capturedCfg.Runtime.HTTPS.Disorder)
	assert.Equal(t, uint8(10), capturedCfg.Runtime.HTTPS.FakeCount)
	assert.Equal(t, []byte{0xff, 0xff}, capturedCfg.Runtime.HTTPS.FakePacket.Raw())
	assert.Equal(t, HTTPSSplitModeSNI, capturedCfg.Runtime.HTTPS.SplitMode)
	assert.Equal(t, uint8(10), capturedCfg.Runtime.HTTPS.ChunkSize)
	assert.False(t, capturedCfg.Runtime.HTTPS.Skip)

	// UDP
	assert.Equal(t, uint8(20), capturedCfg.Runtime.UDP.FakeCount)
	assert.Equal(t, []byte{0xcc, 0xdd}, capturedCfg.Runtime.UDP.FakePacket)
	assert.Equal(t, []byte{0xcc, 0xdd}, capturedCfg.Runtime.UDP.FakePacket)

	// Verify TOML-only fields are preserved
	require.Len(t, capturedCfg.Startup.Rules, 1)
	rule := capturedCfg.Startup.Rules[0]
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
[https]
    split-mode = "chunk"
    chunk-size = 20

[[rules]]
    name = "partial-rule"
    match = { domains = ["example.com"] }
    https = { chunk-size = 50, skip = true }
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
		"--https-fake-count", "10",
	}
	require.NoError(t, cmd.Run(context.Background(), args))
	require.NotNil(t, capturedCfg)
	require.Len(t, capturedCfg.Startup.Rules, 1)

	rule := capturedCfg.Startup.Rules[0]

	// Override-set wins
	assert.Equal(t, uint8(50), rule.Config.HTTPS.ChunkSize, "rule overrides chunk-size")
	assert.True(t, rule.Config.HTTPS.Skip, "rule sets skip explicitly")

	// TOML inherited (rule didn't set, CLI didn't touch)
	assert.Equal(t, HTTPSSplitModeChunk, rule.Config.HTTPS.SplitMode,
		"rule inherits split-mode from static TOML")

	// CLI inherited (rule didn't set, TOML didn't set) — the key claim
	assert.Equal(t, uint8(10), rule.Config.HTTPS.FakeCount,
		"rule inherits fake-count from CLI override")

	// Package default inherited (no one set it)
	assert.False(t, rule.Config.HTTPS.Disorder,
		"rule inherits disorder=false from package default")
}
