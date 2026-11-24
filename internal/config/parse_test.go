package config

import (
	"net"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMustParseBytes(t *testing.T) {
	tcs := []struct {
		name      string
		input     string
		expected  []byte
		wantPanic bool
	}{
		{"single byte", "0x16", []byte{0x16}, false},
		{"multiple bytes", "0x16, 0x03, 0x01", []byte{0x16, 0x03, 0x01}, false},
		{"with spaces", " 0x16 , 0x03 ", []byte{0x16, 0x03}, false},
		{"empty string", "", []byte{}, false},
		{"empty segments", "0x16,,0x03", []byte{0x16, 0x03}, true},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if tc.wantPanic {
				assert.Panics(t, func() {
					assert.Equal(t, tc.expected, MustParseBytes(tc.input))
				})
				return
			}
			assert.NotPanics(t, func() {
				assert.Equal(t, tc.expected, MustParseBytes(tc.input))
			})
		})
	}
}

func TestMustParseHexCSV(t *testing.T) {
	tcs := []struct {
		name     string
		input    []byte
		expected string
	}{
		{"empty", []byte{}, ""},
		{"single", []byte{0x01}, "0x01"},
		{"multiple", []byte{0x01, 0xFF}, "0x01, 0xff"},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, MustParseHexCSV(tc.input))
		})
	}
}

func TestMustParseTCPAddr(t *testing.T) {
	tcs := []struct {
		name      string
		input     string
		wantPanic bool
		assert    func(t *testing.T, ip string, port int)
	}{
		{
			name:      "valid addr",
			input:     "127.0.0.1:8080",
			wantPanic: false,
			assert: func(t *testing.T, ip string, port int) {
				assert.Equal(t, "127.0.0.1", ip)
				assert.Equal(t, 8080, port)
			},
		},
		{
			name:      "valid ipv6 addr",
			input:     "[::1]:8080",
			wantPanic: false,
			assert: func(t *testing.T, ip string, port int) {
				assert.Equal(t, "::1", ip)
				assert.Equal(t, 8080, port)
			},
		},
		{
			name:      "panic on invalid port",
			input:     "127.0.0.1:invalid",
			wantPanic: true,
		},
		{
			name:      "panic on missing port",
			input:     "127.0.0.1",
			wantPanic: true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if tc.wantPanic {
				assert.Panics(t, func() {
					MustParseTCPAddr(tc.input)
				})
			} else {
				addr := MustParseTCPAddr(tc.input)
				tc.assert(t, addr.IP.String(), addr.Port)
			}
		})
	}
}

func TestParseGateway(t *testing.T) {
	tcs := []struct {
		name     string
		input    string
		wantIP   net.IP
		wantZone string
		wantErr  string
	}{
		{
			name:   "private ipv4",
			input:  "192.168.1.1",
			wantIP: net.IPv4(192, 168, 1, 1).To4(),
		},
		{name: "public ipv4", input: "203.0.113.1", wantIP: net.IPv4(203, 0, 113, 1).To4()},
		{
			name:   "link-local ipv4",
			input:  "169.254.1.1",
			wantIP: net.IPv4(169, 254, 1, 1).To4(),
		},
		{
			name:   "ipv4-mapped ipv6 is ipv4",
			input:  "::ffff:192.168.1.1",
			wantIP: net.IPv4(192, 168, 1, 1).To4(),
		},
		{name: "global ipv6", input: "2001:db8::1", wantIP: net.ParseIP("2001:db8::1")},
		{name: "unique local ipv6", input: "fd00::1", wantIP: net.ParseIP("fd00::1")},
		{name: "link-local ipv6", input: "fe80::1", wantIP: net.ParseIP("fe80::1")},
		{
			name:     "link-local ipv6 with a zone",
			input:    "fe80::1%en0",
			wantIP:   net.ParseIP("fe80::1"),
			wantZone: "en0",
		},
		{
			name:     "link-local ipv6 with a numeric zone",
			input:    "fe80::1%4",
			wantIP:   net.ParseIP("fe80::1"),
			wantZone: "4",
		},
		{
			name:    "zone on a global ipv6",
			input:   "2001:db8::1%en0",
			wantErr: "only a link-local IPv6 address may have a zone",
		},
		{
			name:    "zone on an ipv4-mapped address",
			input:   "::ffff:192.168.1.1%en0",
			wantErr: "only a link-local IPv6 address may have a zone",
		},
		{name: "hostname", input: "router.local", wantErr: "is not an IP address"},
		{name: "empty", input: "", wantErr: "is not an IP address"},
		{name: "with port", input: "192.168.1.1:53", wantErr: "is not an IP address"},
		{name: "unspecified ipv4", input: "0.0.0.0", wantErr: "is not a unicast address"},
		{name: "loopback ipv4", input: "127.0.0.1", wantErr: "is not a unicast address"},
		{name: "multicast ipv4", input: "224.0.0.1", wantErr: "is not a unicast address"},
		{
			name:    "broadcast ipv4",
			input:   "255.255.255.255",
			wantErr: "is not a unicast address",
		},
		{name: "unspecified ipv6", input: "::", wantErr: "is not a unicast address"},
		{name: "loopback ipv6", input: "::1", wantErr: "is not a unicast address"},
		{name: "multicast ipv6", input: "ff02::1", wantErr: "is not a unicast address"},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			ip, zone, err := parseGateway(tc.input)
			if tc.wantErr != "" {
				assert.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantIP, ip)
			assert.Equal(t, tc.wantZone, zone)
		})
	}
}

func TestParseGateways(t *testing.T) {
	tcs := []struct {
		name    string
		input   []string
		want    Gateways
		wantErr string
	}{
		{name: "none", input: nil, want: Gateways{}},
		{name: "only empty values", input: []string{"", " "}, want: Gateways{}},
		{
			name:  "ipv4 only",
			input: []string{"192.168.1.1"},
			want:  Gateways{V4: net.IPv4(192, 168, 1, 1).To4()},
		},
		{
			name:  "ipv6 only, with a zone",
			input: []string{"fe80::1%en0"},
			want:  Gateways{V6: net.ParseIP("fe80::1"), V6Zone: "en0"},
		},
		{
			name:  "one of each, in any order, spaces trimmed",
			input: []string{" 2001:db8::1", "192.168.1.1 "},
			want: Gateways{
				V4: net.IPv4(192, 168, 1, 1).To4(),
				V6: net.ParseIP("2001:db8::1"),
			},
		},
		{
			name:    "two ipv4",
			input:   []string{"192.168.1.1", "10.0.0.1"},
			wantErr: "more than one IPv4 gateway",
		},
		{
			name:    "two ipv6",
			input:   []string{"fe80::1%en0", "2001:db8::1"},
			wantErr: "more than one IPv6 gateway",
		},
		{
			name:    "invalid value",
			input:   []string{"192.168.1.1", "127.0.0.1"},
			wantErr: "is not a unicast address",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseGateways(tc.input)
			if tc.wantErr != "" {
				assert.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestParseGatewaysFn(t *testing.T) {
	parse := parseGatewaysFn()

	g, err := parse("192.168.1.1")
	require.NoError(t, err)
	assert.Equal(t, Gateways{V4: net.IPv4(192, 168, 1, 1).To4()}, g)

	g, err = parse([]any{"192.168.1.1", "fe80::1%en0"})
	require.NoError(t, err)
	assert.Equal(t, Gateways{
		V4:     net.IPv4(192, 168, 1, 1).To4(),
		V6:     net.ParseIP("fe80::1"),
		V6Zone: "en0",
	}, g)

	g, err = parse([]any{})
	require.NoError(t, err)
	assert.True(t, g.IsZero(), "an empty array means automatic discovery")

	_, err = parse([]any{"192.168.1.1", int64(1)})
	assert.ErrorContains(t, err, "expected string")

	_, err = parse(int64(1))
	assert.ErrorContains(t, err, "expected string or array")
}

func TestMustParseLogLevel(t *testing.T) {
	tcs := []struct {
		name      string
		input     string
		expected  zerolog.Level
		wantPanic bool
	}{
		{"info", "info", zerolog.InfoLevel, false},
		{"debug", "debug", zerolog.DebugLevel, false},
		{"invalid", "invalid", zerolog.NoLevel, true},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if tc.wantPanic {
				assert.Panics(t, func() {
					MustParseLogLevel(tc.input)
				})
			} else {
				assert.Equal(t, tc.expected, MustParseLogLevel(tc.input))
			}
		})
	}
}

func TestMustParseDNSModeType(t *testing.T) {
	tcs := []struct {
		name      string
		input     string
		expected  DNSModeType
		wantPanic bool
	}{
		{"udp", "udp", DNSModeUDP, false},
		{"system", "system", DNSModeSystem, false},
		{"https", "https", DNSModeHTTPS, false},
		{"invalid", "invalid", 0, true},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if tc.wantPanic {
				assert.Panics(t, func() {
					MustParseDNSModeType(tc.input)
				})
			} else {
				assert.Equal(t, tc.expected, MustParseDNSModeType(tc.input))
			}
		})
	}
}

func TestMustParseHTTPSSplitModeType(t *testing.T) {
	tcs := []struct {
		name      string
		input     string
		expected  HTTPSSplitModeType
		wantPanic bool
	}{
		{"sni", "sni", HTTPSSplitModeSNI, false},
		{"random", "random", HTTPSSplitModeRandom, false},
		{"chunk", "chunk", HTTPSSplitModeChunk, false},
		{"first-byte", "first-byte", HTTPSSplitModeFirstByte, false},
		{"none", "none", HTTPSSplitModeNone, false},
		{"invalid", "invalid", 0, true},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if tc.wantPanic {
				assert.Panics(t, func() {
					mustParseHTTPSSplitModeType(tc.input)
				})
			} else {
				assert.Equal(t, tc.expected, mustParseHTTPSSplitModeType(tc.input))
			}
		})
	}
}

func TestHelperFunctions(t *testing.T) {
	t.Run("parseIntFn", func(t *testing.T) {
		fn := parseIntFn[int](func(i int64) error {
			if i < 0 {
				return net.InvalidAddrError("invalid")
			}
			return nil
		})

		v, err := fn(int64(10))
		assert.NoError(t, err)
		assert.Equal(t, 10, v)

		_, err = fn("invalid")
		assert.Error(t, err)

		_, err = fn(int64(-1))
		assert.Error(t, err)
	})

	t.Run("parseStringFn", func(t *testing.T) {
		fn := parseStringFn(func(s string) error {
			if s == "invalid" {
				return net.InvalidAddrError("invalid")
			}
			return nil
		})

		v, err := fn("valid")
		assert.NoError(t, err)
		assert.Equal(t, "valid", v)

		_, err = fn(123)
		assert.Error(t, err)

		_, err = fn("invalid")
		assert.Error(t, err)
	})

	t.Run("parseBoolFn", func(t *testing.T) {
		fn := parseBoolFn()

		v, err := fn(true)
		assert.NoError(t, err)
		assert.True(t, v)

		_, err = fn("invalid")
		assert.Error(t, err)
	})

	t.Run("parseByteFn", func(t *testing.T) {
		fn := parseByteFn(nil)

		v, err := fn(int64(0x10))
		assert.NoError(t, err)
		assert.Equal(t, byte(0x10), v)

		_, err = fn("invalid")
		assert.Error(t, err)

		_, err = fn(int64(256))
		assert.Error(t, err)

		fnWithVal := parseByteFn(func(b byte) error {
			if b == 0x00 {
				return net.InvalidAddrError("invalid")
			}
			return nil
		})
		_, err = fnWithVal(int64(0x00))
		assert.Error(t, err)
	})
}
