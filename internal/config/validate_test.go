package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCheckDomainPattern(t *testing.T) {
	tcs := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid domain", "example.com", false},
		{"valid subdomain", "sub.example.com", false},
		{"valid wildcard start", "*.example.com", false},
		{"valid globstar start", "**.example.com", false},
		{"valid wildcard segment", "example.*.com", false},
		{"valid single segment", "localhost", false},
		{"invalid empty", "", true},
		{"invalid characters", "ex&ample.com", true},
		{"invalid start with hyphen", "-example.com", true},
		{"valid hyphen in middle", "ex-ample.com", false},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			err := checkDomainPattern(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCheckHostPort(t *testing.T) {
	tcs := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid ipv4 port", "127.0.0.1:8080", false},
		{"valid ipv6 port", "[::1]:8080", false},
		{"invalid port range", "127.0.0.1:70000", true},
		{"invalid ip", "999.999.999.999:8080", true},
		{"missing port", "127.0.0.1", true},
		{"missing ip", ":8080", true},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			err := checkHostPort(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCheckGateway(t *testing.T) {
	tcs := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid private ipv4", "192.168.1.1", false},
		{"valid public ipv4", "203.0.113.1", false},
		{"valid link-local ipv4", "169.254.1.1", false},
		{"ipv6", "fe80::1", true},
		{"hostname", "router.local", true},
		{"empty", "", true},
		{"with port", "192.168.1.1:53", true},
		{"unspecified", "0.0.0.0", true},
		{"loopback", "127.0.0.1", true},
		{"multicast", "224.0.0.1", true},
		{"broadcast", "255.255.255.255", true},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			err := checkGateway(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCheckGateway_IPv6(t *testing.T) {
	for _, v := range []string{"fe80::1", "fe80::1%en0", "2001:db8::1"} {
		assert.ErrorContains(t, checkGateway(v), "IPv6 gateways are not supported yet", v)
	}

	// An IPv4-mapped address is an IPv4 address.
	assert.NoError(t, checkGateway("::ffff:192.168.1.1"))
}

func TestCheckCIDR(t *testing.T) {
	tcs := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid ipv4 cidr", "192.168.1.0/24", false},
		{"valid ipv6 cidr", "2001:db8::/32", false},
		{"invalid cidr", "192.168.1.0", true},
		{"invalid ip", "300.300.300.300/24", true},
		{"ipv4-mapped cidr", "::ffff:10.0.0.0/104", false},
		{"ipv4-mapped /96", "::ffff:0:0/96", false},
		{"ipv4-mapped shorter than /96", "::ffff:0:0/64", true},
		{"ipv6 cidr covering ipv4-mapped", "::/64", false},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			err := checkCIDR(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCheckHTTPSEndpoint(t *testing.T) {
	tcs := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid https", "https://dns.google/dns-query", false},
		{"valid http", "http://dns.google/dns-query", false},
		{"invalid ftp", "ftp://dns.google/dns-query", true},
		{"invalid no scheme", "dns.google/dns-query", true},
		{"empty", "", false},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			err := checkHTTPSEndpoint(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCheckHexBytesStr(t *testing.T) {
	tcs := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid single", "0x16", false},
		{"valid multiple", "0x16, 0x03, 0x01", false},
		{"valid with spaces", " 0x16 , 0x03 ", false},
		{"invalid format", "16, 03", true},
		{"invalid hex", "0xGG", true},
		{"empty", "", false},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			err := checkHexBytesStr(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCheckMatchAttrs(t *testing.T) {
	tcs := []struct {
		name    string
		input   MatchAttrs
		wantErr bool
	}{
		{
			name: "valid match both",
			input: MatchAttrs{
				Domains: []string{"www.google.com"},
				CIDRs:   []string{"192.168.0.0/24"},
			},
			wantErr: false,
		},
		{
			name: "valid match domain",
			input: MatchAttrs{
				Domains: []string{"www.youtube.com"},
			},
			wantErr: false,
		},
		{
			name: "valid match cidr",
			input: MatchAttrs{
				CIDRs: []string{"10.0.0.0/8"},
			},
			wantErr: false,
		},
		{
			name:    "empty match",
			input:   MatchAttrs{},
			wantErr: true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			err := checkMatchAttrs(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCheckRule(t *testing.T) {
	tcs := []struct {
		name    string
		rule    Rule
		wantErr bool
	}{
		{
			name: "valid domain rule",
			rule: Rule{
				Match: &MatchAttrs{
					Domains: []string{"example.com"},
				},
				Config: RuntimeConfig{
					DNS: DNSOptions{Mode: DNSModeUDP},
				},
			},
			wantErr: false,
		},
		{
			name: "valid cidr rule",
			rule: Rule{
				Match: &MatchAttrs{
					CIDRs: []string{"192.168.1.0/24"},
				},
				Config: RuntimeConfig{
					HTTPS: HTTPSOptions{Disorder: true},
				},
			},
			wantErr: false,
		},
		{
			name: "missing match",
			rule: Rule{
				Match: nil,
			},
			wantErr: true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			err := checkRule(tc.rule)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCheckLogLevel(t *testing.T) {
	tcs := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid info", "info", false},
		{"valid debug", "debug", false},
		{"valid warn", "warn", false},
		{"valid error", "error", false},
		{"valid trace", "trace", false},
		{"valid disabled", "disabled", false},
		{"invalid unknown", "unknown", true},
		{"invalid empty", "", true},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			err := checkLogLevel(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
