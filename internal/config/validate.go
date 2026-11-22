package config

import (
	"fmt"
	"math"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/xvzc/spoofdpi/internal/trie"
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

func checkHTTPSSplitMode(v string) error {
	_, _, err := parseSplitMode(v)
	return err
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
	checkUint8  = int64Range(0, math.MaxUint8)
	checkInt8   = int64Range(math.MinInt8, math.MaxInt8)
	checkUint16 = int64Range(0, math.MaxUint16)
	// checkDNSTimeout rejects 0 because an unbounded lookup can hang forever.
	checkDNSTimeout = int64Range(1, math.MaxUint16)
	// checkConnTimeout rejects 0 because a dial without a timeout can hang
	// forever and an idle UDP flow would never be closed.
	checkConnTimeout  = int64Range(1, math.MaxUint16)
	checkUint8NonZero = int64Range(1, math.MaxUint8)
	// checkSeqOffset accepts offsets with |N| < 2^32.
	checkSeqOffset    = int64Range(-math.MaxUint32, math.MaxUint32)
	checkAppMode      = checkOneOf(availableAppModeValues...)
	checkDNSMode      = checkOneOf(availableDNSModeValues...)
	checkLogLevel     = checkOneOf(availableLogLevelValues...)
	checkSegmentFrom  = checkOneOf(availableSegmentFromValues...)
	checkFreeBSDFibID = int64Range(1, 15)
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

// checkGateway accepts an IPv4 unicast address. The gateway MAC is resolved
// via ARP, so IPv6 gateways are not supported yet.
func checkGateway(v string) error {
	if addr, err := netip.ParseAddr(v); err == nil && addr.Is6() && !addr.Is4In6() {
		return fmt.Errorf("value '%s': IPv6 gateways are not supported yet", v)
	}

	ip := net.ParseIP(v).To4()
	if ip == nil {
		return fmt.Errorf("value '%s' is not an IPv4 address", v)
	}

	if !ip.IsGlobalUnicast() && !ip.IsLinkLocalUnicast() {
		return fmt.Errorf("value '%s' is not a unicast address", v)
	}

	return nil
}

// checkCIDR accepts the CIDRs a rule set accepts: an IPv4-mapped prefix,
// which matches IPv4 addresses, must not reach beyond ::ffff:0:0/96.
func checkCIDR(v string) error {
	if _, err := trie.CanonicalCIDR(v); err != nil {
		// The parse error is already descriptive enough,
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
	if len(m.Domains) == 0 && len(m.CIDRs) == 0 {
		return fmt.Errorf("match must have at least one 'domains' or 'cidrs' entry")
	}
	return nil
}

// Validate runs cross-field semantic checks on the resolved Config.
// Format-level validation (e.g. "valid log level") happens earlier
// during UnmarshalTOML / CLI Validators; this pass catches issues that
// can only be detected once defaults+TOML+CLI are merged and rules are
// eager-resolved.
func (c *Config) Validate() error {
	if err := checkHopCountRange(c.Conn); err != nil {
		return err
	}
	for i, rule := range c.Rules {
		if err := checkRule(rule); err != nil {
			return fmt.Errorf("rules[%d]: %w", i, err)
		}
		if err := checkHopCountRange(rule.Config.Conn); err != nil {
			return fmt.Errorf("rules[%d]: %w", i, err)
		}
	}

	return nil
}

func checkHopCountRange(o ConnOptions) error {
	if o.HopCountMin > o.HopCountMax {
		return fmt.Errorf(
			"'hop-count-min' (%d) must not be greater than 'hop-count-max' (%d)",
			o.HopCountMin, o.HopCountMax,
		)
	}
	return nil
}
