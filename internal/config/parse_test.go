package config

import (
	"net"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
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

func TestMustParseDNSQueryType(t *testing.T) {
	tcs := []struct {
		name      string
		input     string
		expected  DNSQueryType
		wantPanic bool
	}{
		{"ipv4", "ipv4", DNSQueryIPv4, false},
		{"ipv6", "ipv6", DNSQueryIPv6, false},
		{"all", "all", DNSQueryAll, false},
		{"invalid", "invalid", 0, true},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if tc.wantPanic {
				assert.Panics(t, func() {
					MustParseDNSQueryType(tc.input)
				})
			} else {
				assert.Equal(t, tc.expected, MustParseDNSQueryType(tc.input))
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
