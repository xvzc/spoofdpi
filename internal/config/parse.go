package config

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/rs/zerolog"
)

func MustParseHexCSV(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	var sb strings.Builder
	// Pre-allocate buffer: "0xHH" (4) + ", " (2) = 6 bytes per element roughly
	sb.Grow(len(data) * 6)

	for i, b := range data {
		if i > 0 {
			sb.WriteString(", ")
		}
		fmt.Fprintf(&sb, "0x%02x", b)
	}

	return sb.String()
}

func MustParseBytes(s string) []byte {
	if err := checkHexBytesStr(s); err != nil {
		panic(err)
	}

	parts := strings.Split(s, ",")

	result := make([]byte, 0, len(parts))

	for _, part := range parts {
		trimmed := strings.TrimSpace(part)

		if trimmed == "" {
			continue
		}

		val, _ := strconv.ParseUint(trimmed, 0, 8)
		result = append(result, byte(val))
	}

	return result
}

func MustParseTCPAddr(s string) net.TCPAddr {
	addr := net.TCPAddr{}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		panic(err)
	}

	addr.IP = net.ParseIP(host)
	addr.Port, err = strconv.Atoi(port)
	if err != nil {
		panic(err)
	}

	return addr
}

func MustParseLogLevel(s string) zerolog.Level {
	level, err := zerolog.ParseLevel(s)
	if err != nil {
		panic(fmt.Sprintf("cannot parse %q to LogLevel", s))
	}

	return level
}

func MustParseServerModeType(s string) AppModeType {
	switch s {
	case "http":
		return AppModeHTTP
	case "socks5":
		return AppModeSOCKS5
	case "tun":
		return AppModeTUN
	default:
		panic(fmt.Sprintf("cannot parse %q to ServerModeType", s))
	}
}

func MustParseDNSModeType(s string) DNSModeType {
	switch s {
	case "udp":
		return DNSModeUDP
	case "system":
		return DNSModeSystem
	case "https":
		return DNSModeHTTPS
	default:
		panic(fmt.Sprintf("cannot parse %q to DNSModeType", s))
	}
}

func MustParseDNSQueryType(s string) DNSQueryType {
	switch s {
	case "ipv4":
		return DNSQueryIPv4
	case "ipv6":
		return DNSQueryIPv6
	case "all": //nolint:goconst
		return DNSQueryAll
	default:
		panic(fmt.Sprintf("cannot parse %q to DNSQueryType", s))
	}
}

func mustParseHTTPSSplitModeType(s string) HTTPSSplitModeType {
	switch s {
	case "sni":
		return HTTPSSplitModeSNI
	case "random":
		return HTTPSSplitModeRandom
	case "chunk":
		return HTTPSSplitModeChunk
	case "first-byte":
		return HTTPSSplitModeFirstByte
	case "none":
		return HTTPSSplitModeNone
	case "custom":
		return HTTPSSplitModeCustom
	default:
		panic(fmt.Sprintf("cannot parse %q to HTTPSSplitModeType", s))
	}
}

func mustParseSegmentFromType(s string) SegmentFromType {
	switch s {
	case "sni":
		return SegmentFromSNI
	case "head":
		return SegmentFromHead
	default:
		panic(fmt.Sprintf("cannot parse %q to SegmentFromType", s))
	}
}

type Integer interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 |
		~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr
}

func parseIntFn[T Integer](validator func(int64) error) func(any) (T, error) {
	return func(v any) (T, error) {
		i64, ok := v.(int64)
		if !ok {
			return 0, fmt.Errorf("expected int64, got %T", v)
		}

		if validator != nil {
			if err := validator(i64); err != nil {
				return 0, err
			}
		}

		return T(i64), nil
	}
}

func parseStringFn(validator func(string) error) func(any) (string, error) {
	return func(v any) (string, error) {
		s, ok := v.(string)
		if !ok {
			return "", fmt.Errorf("expected string, got %T", v)
		}

		if validator != nil {
			if err := validator(s); err != nil {
				return "", err
			}
		}
		return s, nil
	}
}

func parseBoolFn() func(any) (bool, error) {
	return func(v any) (bool, error) {
		b, ok := v.(bool)
		if !ok {
			return false, fmt.Errorf("expected bool, got %T", v)
		}
		return b, nil
	}
}

func parseByteFn(validator func(byte) error) func(any) (byte, error) {
	return func(v any) (byte, error) {
		i64, ok := v.(int64)
		if !ok {
			return 0, fmt.Errorf("expected integer for byte, got %T", v)
		}

		if i64 < 0 || i64 > 255 {
			return 0, fmt.Errorf("value %d out of byte range (0-255)", i64)
		}

		val := byte(i64)

		if validator != nil {
			if err := validator(val); err != nil {
				return 0, err
			}
		}

		return val, nil
	}
}
