package config

import (
	"fmt"
	"math"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

func isOk[T any](p *T, err error) bool {
	if err != nil {
		return false
	}

	if p == nil {
		return false
	}

	return true
}

func checkOneOf(allowed ...string) func(string) error {
	return func(v string) error {
		if slices.Contains(allowed, v) {
			return nil
		}

		return fmt.Errorf(
			"value '%s' is invalid (allowed: %s)",
			v,
			strings.Join(allowed, ", "),
		)
	}
}

func int64Range(mini, maxi int64) func(int64) error {
	return func(v int64) error {
		if v < mini || v > maxi {
			// Using the same error format as your previous examples
			return fmt.Errorf("value %d out of range[%d-%d]", v, mini, maxi)
		}

		return nil
	}
}

var (
	checkUint8          = int64Range(0, math.MaxUint8)
	checkUint16         = int64Range(0, math.MaxUint16)
	checkUint8NonZero   = int64Range(1, math.MaxUint8)
	checkAppMode        = checkOneOf(availableAppModeValues...)
	checkDNSMode        = checkOneOf(availableDNSModeValues...)
	checkDNSQueryType   = checkOneOf(availableDNSQueryValues...)
	checkHTTPSSplitMode = checkOneOf(availableHTTPSModeValues...)
	checkLogLevel       = checkOneOf(availableLogLevelValues...)
	checkSegmentFrom    = checkOneOf(availableSegmentFromValues...)
	checkFreeBSDFibID   = int64Range(1, 15)
)

func checkDomainPattern(v string) error {
	// Label must start/end with alphanumeric, can contain hyphens in between.
	// Wildcards '*' and '**' are allowed as standalone segments.
	rs := `^((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)|\*{2}|\*)(?:\.((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)|\*{2}|\*))*$`
	r, err := regexp.Compile(rs)
	if err != nil {
		return err
	}

	if !r.MatchString(v) {
		return fmt.Errorf("invalid domain pattern")
	}

	return nil
}

func checkHostPort(v string) error {
	host, port, err := net.SplitHostPort(v)
	if err != nil {
		return err
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("invalid IP address format")
	}

	portInt, err := strconv.Atoi(port)
	if err != nil {
		return err
	}

	return checkUint16(int64(portInt))
}

// checkPortRange validates if the input is a single port, a range, or "all".
func checkPortRange(v string) error {
	// 1. Check for "all" keyword
	if strings.ToLower(v) == "all" { //nolint:goconst
		return nil
	}

	// 2. Regex for single port (e.g., "8080") or range (e.g., "0-8000")
	// Allowing leading/trailing spaces for robustness if needed, but strict is better.
	re := regexp.MustCompile(`^(\d+)(-(\d+))?$`)
	matches := re.FindStringSubmatch(v)

	if matches == nil {
		return fmt.Errorf(
			"invalid port format: '%s' (expected '8080', '0-8000', or 'all')",
			v,
		)
	}

	// Helper to validate numeric port range
	checkPort := func(s string) (int, error) {
		p, err := strconv.Atoi(s)
		if err != nil || p < 0 || p > 65535 {
			return 0, fmt.Errorf("port %s out of range [0-65535]", s)
		}
		return p, nil
	}

	// 3. Case: Single Port (matches[1] contains the number, matches[3] is empty)
	if matches[3] == "" {
		_, err := checkPort(matches[1])
		return err
	}

	// 4. Case: Port Range (matches[1] is from, matches[3] is end)
	from, err := checkPort(matches[1])
	if err != nil {
		return err
	}
	to, err := checkPort(matches[3])
	if err != nil {
		return err
	}

	if from > to {
		return fmt.Errorf(
			"invalid range: from-port %d is greater than to-port %d",
			from,
			to,
		)
	}

	return nil
}

func checkCIDR(v string) error {
	_, _, err := net.ParseCIDR(v)
	if err != nil {
		// Go's net package error is already descriptive enough,
		// but we wrap it to give context about the specific value.
		return fmt.Errorf("wrongCIDR '%s': %w", v, err)
	}
	return nil
}

func checkHTTPSEndpoint(v string) error {
	if v != "" {
		if ok, err := regexp.MatchString("^https?://", v); !ok ||
			err != nil {
			return fmt.Errorf("should start with 'https://'")
		}
	}

	return nil
}

func checkHexBytesStr(s string) error {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return nil
	}

	r := regexp.MustCompile(
		`^(\s*0x[0-9a-fA-F]{2}\s*)(,\s*0x[0-9a-fA-F]{2}\s*)*$`,
	)

	if !r.MatchString(trimmed) {
		return fmt.Errorf("invalid byte array format")
	}

	return nil
}

func checkRule(r Rule) error {
	if r.Match == nil {
		return fmt.Errorf("rule must have match attribute")
	}

	return nil
}

func checkMatchAttrs(m MatchAttrs) error {
	for _, addr := range m.Addrs {
		if len(addr.CIDR.IP) == 0 {
			return fmt.Errorf("addr rule must have cidr attribute")
		}
		if addr.PortFrom == 0 && addr.PortTo == 0 {
			return fmt.Errorf("addr rule must have port attribute")
		}
	}

	return nil
}

// Validate runs cross-field semantic checks on the resolved Config.
// Format-level validation (e.g. "valid log level") happens earlier
// during UnmarshalTOML / CLI Validators; this pass catches issues that
// can only be detected once defaults+TOML+CLI are merged and rules are
// eager-resolved.
func (c *Config) Validate() error {
	for i, rule := range c.Startup.Rules {
		if err := checkRule(rule); err != nil {
			return fmt.Errorf("rules[%d]: %w", i, err)
		}
	}
	return nil
}
