package probe

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseTarget(t *testing.T) {
	for _, in := range []string{"a.test", "example.com", "x", "1.2.3.4", "192.0.2.1"} {
		t.Run(in, func(t *testing.T) {
			got, err := ParseTarget(in)
			require.NoError(t, err)
			assert.Equal(t, Target{Input: in, Host: in}, got)
		})
	}
}

func TestParseTarget_Normalized(t *testing.T) {
	for _, tc := range []struct{ in, host string }{
		{"WWW.Example.COM", "www.example.com"},
		{"a.test.", "a.test."},
		{"Bücher.example", "xn--bcher-kva.example"},
		{"例え.テスト", "xn--r8jz45g.xn--zckzah"},
	} {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseTarget(tc.in)
			require.NoError(t, err)
			assert.Equal(t, Target{Input: tc.in, Host: tc.host}, got,
				"the input is kept for the report")
		})
	}
}

func TestParseTarget_Rejected(t *testing.T) {
	tcs := []struct {
		in        string
		wantError string
	}{
		{in: "", wantError: `host is missing`},
		{
			in:        "https://a.test",
			wantError: `"https://a.test": give the host only, without a scheme`,
		},
		{
			in:        "quic://a.test:443",
			wantError: `"quic://a.test:443": give the host only, without a scheme`,
		},
		{in: "a.test/", wantError: `"a.test/": give the host only, without a path`},
		{in: "a.test?q=1", wantError: `"a.test?q=1": give the host only, without a path`},
		{in: "a.test#x", wantError: `"a.test#x": give the host only, without a path`},
		{in: "u@a.test", wantError: `"u@a.test": give the host only, without user info`},
		{
			in:        "2001:db8::1",
			wantError: `"2001:db8::1": only host names and IPv4 addresses are probed`,
		},
		{
			in:        "[2001:db8::1]",
			wantError: `"[2001:db8::1]": only host names and IPv4 addresses are probed`,
		},
		{
			in:        "[2001:db8::1]:443",
			wantError: `"[2001:db8::1]:443": only host names and IPv4 addresses are probed`,
		},
		{
			in:        "::ffff:192.0.2.1",
			wantError: `"::ffff:192.0.2.1": only host names and IPv4 addresses are probed`,
		},
		{
			in:        "a.test:443",
			wantError: `"a.test:443": give the host only, without a port (443 is used)`,
		},
		{
			in:        "192.0.2.1:80",
			wantError: `"192.0.2.1:80": give the host only, without a port (443 is used)`,
		},
		{
			in:        ":443",
			wantError: `":443": give the host only, without a port (443 is used)`,
		},
		{in: "a test", wantError: `"a test": not a host name`},
		{in: "1.2.3", wantError: `"1.2.3": not an IPv4 address`},
		{in: "256.1.1.1", wantError: `"256.1.1.1": not an IPv4 address`},
		{in: "01.2.3.4", wantError: `"01.2.3.4": not an IPv4 address`},
		{in: "1.2.3.4.", wantError: `"1.2.3.4.": not an IPv4 address`},
		{in: "123", wantError: `"123": not an IPv4 address`},
		{
			in:        "a\u200d.test",
			wantError: `"a\u200d.test": not a valid host name: idna: `,
		},
		{in: "a.test\n", wantError: `"a.test\n": not a host name`},
		{in: "a\x00b", wantError: `"a\x00b": not a host name`},
	}
	for _, tc := range tcs {
		t.Run(tc.in, func(t *testing.T) {
			_, err := ParseTarget(tc.in)
			require.Error(t, err)
			assert.True(t, strings.HasPrefix(err.Error(), tc.wantError), err.Error())
		})
	}
}

func TestCheckTargets(t *testing.T) {
	assert.NoError(t, checkTargets([]string{"a.test", "b.test"}))
	assert.EqualError(t, checkTargets([]string{"a.test", "https://b.test"}),
		`"https://b.test": give the host only, without a scheme`)
}
