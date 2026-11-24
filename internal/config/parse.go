package config

import (
	"fmt"
	"math"
	"net"
	"net/netip"
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

// parseGateway parses a gateway address: a global unicast or link-local
// IPv4 or IPv6 address. Only a link-local IPv6 address may have a zone,
// such as "fe80::1%en0". An IPv4-mapped IPv6 address is an IPv4 address.
func parseGateway(s string) (ip net.IP, zone string, err error) {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return nil, "", fmt.Errorf("value '%s' is not an IP address", s)
	}
	zone = addr.Zone()
	addr = addr.WithZone("").Unmap()

	if !addr.IsGlobalUnicast() && !addr.IsLinkLocalUnicast() {
		return nil, "", fmt.Errorf("value '%s' is not a unicast address", s)
	}
	if zone != "" && (addr.Is4() || !addr.IsLinkLocalUnicast()) {
		return nil, "", fmt.Errorf(
			"value '%s': only a link-local IPv6 address may have a zone", s,
		)
	}

	return net.IP(addr.AsSlice()), zone, nil
}

// parseGateways parses the values of the gateway option: at most one
// address per family. Empty values are skipped, so no value, or only
// empty ones, leaves every gateway to discovery.
func parseGateways(values []string) (Gateways, error) {
	var g Gateways
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		ip, zone, err := parseGateway(v)
		if err != nil {
			return Gateways{}, err
		}

		if len(ip) == net.IPv4len {
			if g.V4 != nil {
				return Gateways{}, fmt.Errorf(
					"more than one IPv4 gateway: '%s' and '%s'", g.V4, v,
				)
			}
			g.V4 = ip
			continue
		}
		if g.V6 != nil {
			return Gateways{}, fmt.Errorf(
				"more than one IPv6 gateway: '%s' and '%s'", g.V6, v,
			)
		}
		g.V6, g.V6Zone = ip, zone
	}
	return g, nil
}

// parseGatewaysFn parses the TOML gateway option: an address, or an array
// of addresses (see parseGateways).
func parseGatewaysFn() func(any) (Gateways, error) {
	return func(v any) (Gateways, error) {
		switch v := v.(type) {
		case string:
			return parseGateways([]string{v})
		case []any:
			values := make([]string, len(v))
			for i, item := range v {
				s, ok := item.(string)
				if !ok {
					return Gateways{}, fmt.Errorf("expected string, got %T", item)
				}
				values[i] = s
			}
			return parseGateways(values)
		default:
			return Gateways{}, fmt.Errorf("expected string or array, got %T", v)
		}
	}
}

// DefaultChunkSize is the chunk size of split-mode "chunk" without a size.
const DefaultChunkSize uint8 = 35

// parseSplitMode parses a split-mode value: one of the modes, or
// "chunk:N" for chunks of N bytes (1-255). Bare "chunk" means chunks of
// DefaultChunkSize bytes. size is 0 for modes other than chunk.
func parseSplitMode(s string) (mode HTTPSSplitModeType, size uint8, err error) {
	if s == "chunk" {
		return HTTPSSplitModeChunk, DefaultChunkSize, nil
	}
	if n, ok := strings.CutPrefix(s, "chunk:"); ok {
		v, perr := strconv.ParseInt(n, 10, 64)
		if perr != nil || v < 1 || v > math.MaxUint8 {
			return 0, 0, fmt.Errorf(
				"value '%s' has an invalid chunk size (allowed: 1-%d)", s, math.MaxUint8,
			)
		}
		return HTTPSSplitModeChunk, uint8(v), nil
	}
	if err := checkOneOf(availableHTTPSModeValues...)(s); err != nil {
		return 0, 0, err
	}
	return mustParseHTTPSSplitModeType(s), 0, nil
}

func mustParseSplitMode(s string) (HTTPSSplitModeType, uint8) {
	mode, size, err := parseSplitMode(s)
	if err != nil {
		panic(err)
	}
	return mode, size
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
