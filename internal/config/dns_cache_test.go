package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The removed 'cache' option is still accepted, with a warning, and has no
// effect: DNS answers are always cached.
func TestDNSCacheDeprecated(t *testing.T) {
	const warnTOML = "'dns.cache' is deprecated and ignored; DNS answers are always cached"

	t.Run("dns section", func(t *testing.T) {
		cfg, warns := runWithTOML(t, "[dns]\ncache = true\nqtype = \"all\"\n")
		assert.Equal(t, DNSQueryAll, cfg.DNS.QType)
		assert.Contains(t, warns, warnTOML)
	})

	t.Run("rule dns section", func(t *testing.T) {
		cfg, warns := runWithTOML(t, `
[[rules]]
name = "r"
match = { domains = ["example.com"] }
dns = { cache = false, qtype = "ipv6" }
`)
		require.Len(t, cfg.Rules, 1)
		assert.Equal(t, DNSQueryIPv6, cfg.Rules[0].Config.DNS.QType)
		assert.Contains(t, warns, "rule 0: "+warnTOML)
	})

	t.Run("flag", func(t *testing.T) {
		_, warns := runWithTOML(t, "", "--dns-cache")
		assert.Contains(
			t,
			warns,
			"'--dns-cache' is deprecated and ignored; DNS answers are always cached",
		)
	})

	t.Run("no warning without the option", func(t *testing.T) {
		_, warns := runWithTOML(t, "[dns]\nqtype = \"all\"\n")
		assert.Empty(t, warns)
	})
}
