package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

func TestSearchTomlFile(t *testing.T) {
	tcs := []struct {
		name       string
		customDir  string
		lookupDirs []string
		setup      func(t *testing.T) (string, []string)
		assert     func(t *testing.T, path string, err error)
	}{
		{
			name:      "custom dir exists",
			customDir: "custom.toml",
			setup: func(t *testing.T) (string, []string) {
				tmpDir := t.TempDir()
				path := filepath.Join(tmpDir, "custom.toml")
				err := os.WriteFile(path, []byte{}, 0o644)
				assert.NoError(t, err)
				return path, nil
			},
			assert: func(t *testing.T, path string, err error) {
				assert.NoError(t, err)
				assert.NotEmpty(t, path)
			},
		},
		{
			name:      "custom dir not found",
			customDir: "nonexistent.toml",
			setup: func(t *testing.T) (string, []string) {
				return "nonexistent.toml", nil
			},
			assert: func(t *testing.T, path string, err error) {
				assert.Error(t, err)
				assert.Empty(t, path)
			},
		},
		{
			name: "found in lookup dirs",
			setup: func(t *testing.T) (string, []string) {
				tmpDir := t.TempDir()
				path := filepath.Join(tmpDir, "lookup.toml")
				err := os.WriteFile(path, []byte{}, 0o644)
				assert.NoError(t, err)
				return "", []string{"nonexistent", path}
			},
			assert: func(t *testing.T, path string, err error) {
				assert.NoError(t, err)
				assert.NotEmpty(t, path)
			},
		},
		{
			name: "not found in lookup dirs",
			setup: func(t *testing.T) (string, []string) {
				return "", []string{"nonexistent"}
			},
			assert: func(t *testing.T, path string, err error) {
				assert.NoError(t, err)
				assert.Empty(t, path)
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			customDir, lookupDirs := tc.setup(t)
			path, err := searchTomlFile(customDir, lookupDirs)
			tc.assert(t, path, err)
		})
	}
}

func TestFindFrom(t *testing.T) {
	tcs := []struct {
		name      string
		data      map[string]any
		key       string
		parser    func(any) (uint8, error)
		errPtrVal error
		assert    func(t *testing.T, val *uint8, err error)
	}{
		{
			name:   "valid value",
			data:   map[string]any{"key": int64(10)},
			key:    "key",
			parser: parseIntFn[uint8](checkUint8),
			assert: func(t *testing.T, val *uint8, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, val)
				assert.Equal(t, uint8(10), *val)
			},
		},
		{
			name:   "missing key",
			data:   map[string]any{},
			key:    "key",
			parser: parseIntFn[uint8](checkUint8),
			assert: func(t *testing.T, val *uint8, err error) {
				assert.NoError(t, err)
				assert.Nil(t, val)
			},
		},
		{
			name:   "invalid type",
			data:   map[string]any{"key": "string"},
			key:    "key",
			parser: parseIntFn[uint8](checkUint8),
			assert: func(t *testing.T, val *uint8, err error) {
				assert.Error(t, err)
				assert.Nil(t, val)
			},
		},
		{
			name: "validation error",
			data: map[string]any{"key": int64(10)},
			key:  "key",
			parser: func(v any) (uint8, error) {
				return 0, errors.New("validation failed")
			},
			assert: func(t *testing.T, val *uint8, err error) {
				assert.Error(t, err)
				assert.Nil(t, val)
			},
		},
		{
			name:      "existing error",
			data:      map[string]any{"key": int64(10)},
			key:       "key",
			parser:    parseIntFn[uint8](checkUint8),
			errPtrVal: errors.New("existing error"),
			assert: func(t *testing.T, val *uint8, err error) {
				assert.Error(t, err)
				assert.Nil(t, val)
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			if tc.errPtrVal != nil {
				err = tc.errPtrVal
			}
			val := findFrom(tc.data, tc.key, tc.parser, &err)
			tc.assert(t, val, err)
		})
	}
}

// Dummy struct for testing findStructFrom and findStructSliceFrom
type testStruct struct {
	Val int `toml:"val"`
}

func (ts *testStruct) UnmarshalTOML(data any) error {
	m, ok := data.(map[string]any)
	if !ok {
		return fmt.Errorf("invalid type")
	}
	if v, ok := m["val"].(int64); ok {
		ts.Val = int(v)
		return nil
	}
	if v, ok := m["val"].(int); ok {
		ts.Val = v
		return nil
	}
	return fmt.Errorf("invalid val field")
}

func TestFindStructFrom(t *testing.T) {
	tcs := []struct {
		name      string
		data      map[string]any
		key       string
		errPtrVal error
		assert    func(t *testing.T, val *testStruct, err error)
	}{
		{
			name: "valid struct",
			data: map[string]any{"key": map[string]any{"val": 10}},
			key:  "key",
			assert: func(t *testing.T, val *testStruct, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, val)
				assert.Equal(t, 10, val.Val)
			},
		},
		{
			name: "missing key",
			data: map[string]any{},
			key:  "key",
			assert: func(t *testing.T, val *testStruct, err error) {
				assert.NoError(t, err)
				assert.Nil(t, val)
			},
		},
		{
			name: "unmarshal error",
			data: map[string]any{"key": map[string]any{"val": "invalid"}},
			key:  "key",
			assert: func(t *testing.T, val *testStruct, err error) {
				assert.Error(t, err)
				assert.Nil(t, val)
			},
		},
		{
			name:      "existing error",
			data:      map[string]any{"key": map[string]any{"val": 10}},
			key:       "key",
			errPtrVal: errors.New("existing"),
			assert: func(t *testing.T, val *testStruct, err error) {
				assert.Error(t, err)
				assert.Nil(t, val)
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			if tc.errPtrVal != nil {
				err = tc.errPtrVal
			}
			val := findStructFrom[testStruct](tc.data, tc.key, &err)
			tc.assert(t, val, err)
		})
	}
}

func TestFindStructSliceFrom(t *testing.T) {
	tcs := []struct {
		name      string
		data      map[string]any
		key       string
		errPtrVal error
		assert    func(t *testing.T, list []testStruct, err error)
	}{
		{
			name: "valid list []any",
			data: map[string]any{
				"key": []any{
					map[string]any{"val": 1},
					map[string]any{"val": 2},
				},
			},
			key: "key",
			assert: func(t *testing.T, list []testStruct, err error) {
				assert.NoError(t, err)
				assert.Len(t, list, 2)
				assert.Equal(t, 1, list[0].Val)
				assert.Equal(t, 2, list[1].Val)
			},
		},
		{
			name: "valid list []map[string]any",
			data: map[string]any{
				"key": []map[string]any{
					{"val": 1},
					{"val": 2},
				},
			},
			key: "key",
			assert: func(t *testing.T, list []testStruct, err error) {
				assert.NoError(t, err)
				assert.Len(t, list, 2)
				assert.Equal(t, 1, list[0].Val)
				assert.Equal(t, 2, list[1].Val)
			},
		},
		{
			name: "missing key",
			data: map[string]any{},
			key:  "key",
			assert: func(t *testing.T, list []testStruct, err error) {
				assert.NoError(t, err)
				assert.Nil(t, list)
			},
		},
		{
			name: "invalid list type",
			data: map[string]any{"key": 1},
			key:  "key",
			assert: func(t *testing.T, list []testStruct, err error) {
				assert.Error(t, err)
				assert.Nil(t, list)
			},
		},
		{
			name: "item unmarshal error",
			data: map[string]any{
				"key": []any{
					map[string]any{"val": "invalid"},
				},
			},
			key: "key",
			assert: func(t *testing.T, list []testStruct, err error) {
				assert.Error(t, err)
				assert.Nil(t, list)
			},
		},
		{
			name:      "existing error",
			data:      map[string]any{"key": []any{}},
			key:       "key",
			errPtrVal: errors.New("existing"),
			assert: func(t *testing.T, list []testStruct, err error) {
				assert.Error(t, err)
				assert.Nil(t, list)
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			if tc.errPtrVal != nil {
				err = tc.errPtrVal
			}
			list := findStructSliceFrom[testStruct](tc.data, tc.key, &err)
			tc.assert(t, list, err)
		})
	}
}

func TestFindSliceFrom(t *testing.T) {
	tcs := []struct {
		name      string
		data      map[string]any
		key       string
		errPtrVal error
		assert    func(t *testing.T, list []uint16, err error)
	}{
		{
			name: "valid list []any",
			data: map[string]any{"key": []any{int64(1), int64(2), int64(3)}},
			key:  "key",
			assert: func(t *testing.T, list []uint16, err error) {
				assert.NoError(t, err)
				assert.Equal(t, []uint16{1, 2, 3}, list)
			},
		},
		{
			name: "valid list []T",
			data: map[string]any{"key": []any{int64(1), int64(2), int64(3)}},
			key:  "key",
			assert: func(t *testing.T, list []uint16, err error) {
				assert.NoError(t, err)
				assert.Equal(t, []uint16{1, 2, 3}, list)
			},
		},
		{
			name: "missing key",
			data: map[string]any{},
			key:  "key",
			assert: func(t *testing.T, list []uint16, err error) {
				assert.NoError(t, err)
				assert.Nil(t, list)
			},
		},
		{
			name: "invalid type",
			data: map[string]any{"key": 1},
			key:  "key",
			assert: func(t *testing.T, list []uint16, err error) {
				assert.Error(t, err)
				assert.Nil(t, list)
			},
		},
		{
			name: "convert error",
			data: map[string]any{"key": []any{"string"}},
			key:  "key",
			assert: func(t *testing.T, list []uint16, err error) {
				assert.Error(t, err)
				assert.Nil(t, list)
			},
		},
		{
			name:      "existing error",
			data:      map[string]any{"key": []any{1}},
			key:       "key",
			errPtrVal: errors.New("existing"),
			assert: func(t *testing.T, list []uint16, err error) {
				assert.Error(t, err)
				assert.Nil(t, list)
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			if tc.errPtrVal != nil {
				err = tc.errPtrVal
			}
			list := findSliceFrom(tc.data, tc.key, parseIntFn[uint16](checkUint16), &err)
			tc.assert(t, list, err)
		})
	}
}

func TestFromTomlFile(t *testing.T) {
	t.Run("full valid config", func(t *testing.T) {
		tomlContent := `
				[app]
				log-level = "debug"
				no-tui = true
				auto-configure-network = true
				mode = "socks5"
				listen-addr = "127.0.0.1:8080"
			[connection]
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

			[policy]
				[[policy.overrides]]
					name = "test-rule"
					priority = 100
					block = true
					match = { 
						domain = ["example.com"], 
						addr = [
							{cidr = "192.168.1.0/24", port = "80-443"}
						]
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
		configPath := filepath.Join(tmpDir, "config.toml")

		err := os.WriteFile(configPath, []byte(tomlContent), 0o644)
		assert.NoError(t, err)

		cfg := DefaultConfig()
		err = fromTomlFile(configPath, cfg)
		assert.NoError(t, err)
		assert.NotNil(t, cfg)

		if cfg == nil {
			return
		}

		// Finalize promotes captured raw overrides into resolved Rules.
		assert.NoError(t, cfg.Finalize())

		assert.Equal(t, "127.0.0.1:8080", cfg.Startup.App.ListenAddr.String())
		assert.Equal(t, time.Duration(1000*time.Millisecond), cfg.Runtime.Conn.DNSTimeout)
		assert.Equal(t, time.Duration(1000*time.Millisecond), cfg.Runtime.Conn.TCPTimeout)
		assert.Equal(
			t,
			time.Duration(1000*time.Millisecond),
			cfg.Runtime.Conn.UDPIdleTimeout,
		)
		assert.Equal(t, zerolog.DebugLevel, cfg.Startup.App.LogLevel)
		assert.True(t, cfg.Startup.App.NoTUI)
		assert.True(t, cfg.Startup.App.AutoConfigureNetwork)
		assert.Equal(t, AppModeSOCKS5, cfg.Startup.App.Mode)
		assert.Equal(t, "8.8.8.8:53", cfg.Runtime.DNS.Addr.String())
		assert.True(t, cfg.Runtime.DNS.Cache)
		assert.Equal(t, DNSModeHTTPS, cfg.Runtime.DNS.Mode)
		assert.Equal(t, "https://1.1.1.1/dns-query", cfg.Runtime.DNS.HTTPSURL)
		assert.Equal(t, DNSQueryIPv4, cfg.Runtime.DNS.QType)
		assert.Equal(t, uint8(100), cfg.Runtime.Conn.DefaultFakeTTL)
		assert.True(t, cfg.Runtime.HTTPS.Disorder)
		assert.Equal(t, uint8(5), cfg.Runtime.HTTPS.FakeCount)
		assert.Equal(t, []byte{0x01, 0x02, 0x03}, cfg.Runtime.HTTPS.FakePacket.Raw())
		assert.Equal(t, HTTPSSplitModeChunk, cfg.Runtime.HTTPS.SplitMode)
		assert.Equal(t, uint8(20), cfg.Runtime.HTTPS.ChunkSize)
		assert.True(t, cfg.Runtime.HTTPS.Skip)

		// Resolve policy overrides on top of the finalized base RuntimeConfig.
		raw, err := extractRawOverrides(configPath)
		assert.NoError(t, err)
		rules, err := resolveRules(raw, cfg.Runtime)
		assert.NoError(t, err)
		assert.Len(t, rules, 1)

		override := rules[0]

		assert.Equal(t, "test-rule", override.Name)
		assert.Equal(t, uint16(100), override.Priority)

		assert.Equal(t, "example.com", override.Match.Domains[0])
		assert.Equal(t, "192.168.1.0/24", override.Match.Addrs[0].CIDR.String())
		assert.Equal(t, uint16(80), override.Match.Addrs[0].PortFrom)
		assert.Equal(t, uint16(443), override.Match.Addrs[0].PortTo)

		assert.Equal(t, DNSModeUDP, override.Runtime.DNS.Mode)
		assert.Equal(t, "8.8.4.4:53", override.Runtime.DNS.Addr.String())
		assert.Equal(t, "https://8.8.8.8/dns-query", override.Runtime.DNS.HTTPSURL)
		assert.Equal(t, DNSQueryIPv6, override.Runtime.DNS.QType)
		assert.True(t, override.Block)
		assert.False(t, override.Runtime.DNS.Cache)

		assert.False(t, override.Runtime.HTTPS.Disorder)
		assert.Equal(t, uint8(2), override.Runtime.HTTPS.FakeCount)
		assert.Equal(t, []byte{0xAA, 0xBB}, override.Runtime.HTTPS.FakePacket.Raw())
		assert.Equal(t, HTTPSSplitModeSNI, override.Runtime.HTTPS.SplitMode)
		assert.Equal(t, uint8(10), override.Runtime.HTTPS.ChunkSize)
		assert.True(t, override.Runtime.HTTPS.Skip)
	})
}
