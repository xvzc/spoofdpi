package probe

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/config"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "spoofdpi.toml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o644))
	return path
}

const dnsTOML = `
[dns]
mode = "https"
https-url = "https://192.0.2.53/dns-query"
addr = "192.0.2.53:53"
qtype = "ipv6"
cache = true
timeout = 1000

[[rules]]
name = "rule dns is not applied"
match = { domains = ["a.test"] }
dns = { mode = "system" }
`

func TestDNSOptions_FromConfig(t *testing.T) {
	path := writeConfig(t, dnsTOML)
	got, used, err := dnsOptions(false, path, nil)
	require.NoError(t, err)
	assert.Equal(t, path, used)
	assert.Equal(t, config.DNSOptions{
		Mode:     config.DNSModeHTTPS,
		Addr:     net.TCPAddr{IP: net.ParseIP("192.0.2.53"), Port: 53},
		HTTPSURL: "https://192.0.2.53/dns-query",
		QType:    config.DNSQueryIPv4,
		Timeout:  time.Second,
	}, normalizeIP(got))
}

func TestDNSOptions_FlagsOverrideConfig(t *testing.T) {
	path := writeConfig(t, dnsTOML)
	got, _, err := dnsOptions(false, path, []func(*config.DNSOptions){
		func(o *config.DNSOptions) { o.Mode = config.DNSModeUDP },
		func(o *config.DNSOptions) { o.QType = config.DNSQueryAll },
	})
	require.NoError(t, err)
	assert.Equal(t, config.DNSModeUDP, got.Mode, "the flag wins")
	assert.Equal(t, "https://192.0.2.53/dns-query", got.HTTPSURL, "the config is kept")
	assert.Equal(t, config.DNSQueryIPv4, got.QType, "IPv4 is forced")
}

func TestDNSOptions_Clean(t *testing.T) {
	got, used, err := dnsOptions(
		true,
		"/nonexistent/spoofdpi.toml",
		[]func(*config.DNSOptions){
			func(o *config.DNSOptions) { o.Timeout = 3 * time.Second },
		},
	)
	require.NoError(t, err, "--clean does not read --config")
	assert.Empty(t, used)
	want := config.DefaultConfig().DNS
	want.Timeout = 3 * time.Second
	assert.Equal(t, want, got)
}

func TestDNSOptions_MissingConfig(t *testing.T) {
	_, _, err := dnsOptions(false, "/nonexistent/spoofdpi.toml", nil)
	assert.ErrorContains(t, err, "/nonexistent/spoofdpi.toml")
}

func TestDNSOptions_InvalidConfig(t *testing.T) {
	path := writeConfig(t, "[dns]\nmode = \"carrier-pigeon\"\n")
	_, _, err := dnsOptions(false, path, nil)
	assert.ErrorContains(t, err, path)
}

func TestDescribeDNS(t *testing.T) {
	opts := config.DefaultConfig().DNS
	assert.Equal(
		t,
		"udp (8.8.8.8:53), no config file (--clean)",
		describeDNS(opts, "", true),
	)
	assert.Equal(t, "udp (8.8.8.8:53), no config file", describeDNS(opts, "", false))

	opts.Mode = config.DNSModeHTTPS
	opts.HTTPSURL = "https://192.0.2.53/dns-query"
	assert.Equal(t,
		"https (https://192.0.2.53/dns-query), config /etc/spoofdpi.toml",
		describeDNS(opts, "/etc/spoofdpi.toml", false))

	opts.Mode = config.DNSModeSystem
	assert.Equal(t, "system, no config file", describeDNS(opts, "", false))
}

// normalizeIP makes the address of opts comparable with net.ParseIP's.
func normalizeIP(opts config.DNSOptions) config.DNSOptions {
	opts.Addr.IP = opts.Addr.IP.To16()
	return opts
}
