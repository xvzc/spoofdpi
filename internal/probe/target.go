package probe

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"unicode"

	"golang.org/x/net/idna"
)

// Target is a site to probe, parsed from a --url value.
type Target struct {
	// Input is the --url value as given.
	Input string
	// Host is the host name, in lower case and with an internationalized
	// name in its ASCII (punycode) form, or the IPv4 literal.
	Host string
}

// The ports every target is measured on: TCP and the DPI checks on
// httpsPort, UDP and the QUIC check on quicPort.
const (
	httpsPort = 443
	quicPort  = 443
)

// ParseTarget parses a --url value: a host name or an IPv4 literal,
// without scheme, port or path. Every target measures TCP and UDP, the
// DPI checks of its https section and the QUIC check of its quic section.
// The host is lowercased, and an internationalized name converted to
// punycode, as a browser sends it in the SNI.
func ParseTarget(s string) (Target, error) {
	switch {
	case s == "":
		return Target{}, errors.New("host is missing")
	case strings.Contains(s, "://"):
		return Target{}, fmt.Errorf("%q: give the host only, without a scheme", s)
	case strings.ContainsAny(s, "/?#"):
		return Target{}, fmt.Errorf("%q: give the host only, without a path", s)
	case strings.Contains(s, "@"):
		return Target{}, fmt.Errorf("%q: give the host only, without user info", s)
	case strings.ContainsAny(s, "[]") || isIPv6(s):
		return Target{}, fmt.Errorf("%q: only host names and IPv4 addresses are probed", s)
	case strings.Contains(s, ":"):
		return Target{}, fmt.Errorf(
			"%q: give the host only, without a port (443 is used)",
			s,
		)
	case strings.ContainsFunc(s, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	}):
		return Target{}, fmt.Errorf("%q: not a host name", s)
	case isDottedNumbers(s):
		// A resolver would take such a name for an address too.
		if a, err := netip.ParseAddr(s); err != nil || !a.Is4() {
			return Target{}, fmt.Errorf("%q: not an IPv4 address", s)
		}
		return Target{Input: s, Host: s}, nil
	}
	host := strings.ToLower(s)
	if !isASCII(host) {
		ascii, err := idna.Lookup.ToASCII(host)
		if err != nil {
			return Target{}, fmt.Errorf("%q: not a valid host name: %w", s, err)
		}
		host = ascii
	}
	return Target{Input: s, Host: host}, nil
}

// isDottedNumbers reports whether s is made of digits and dots only.
func isDottedNumbers(s string) bool {
	return strings.Trim(s, "0123456789.") == ""
}

// isASCII reports whether s has only ASCII characters.
func isASCII(s string) bool {
	return !strings.ContainsFunc(s, func(r rune) bool { return r > unicode.MaxASCII })
}

// isIPv6 reports whether s is an IPv6 literal, an IPv4-mapped one
// included.
func isIPv6(s string) bool {
	a, err := netip.ParseAddr(s)
	return err == nil && !a.Is4()
}

// checkTargets validates --url values. Its errors do not name the flag:
// the flag parser adds it.
func checkTargets(values []string) error {
	for _, v := range values {
		if _, err := ParseTarget(v); err != nil {
			return err
		}
	}
	return nil
}
