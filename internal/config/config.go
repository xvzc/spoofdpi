package config

import (
	"fmt"
	"net"
)

// Config groups configuration by lifecycle:
//
//   - Startup is read once at boot (logger setup, mode selection, building
//     the matcher from policy overrides) and is not needed at request time.
//   - Runtime is read on every request (per-traffic decisions about DPI
//     bypass, DNS resolution, timeouts) and travels with handlers.
type Config struct {
	Startup StartupConfig
	Runtime RuntimeConfig

	// WarnMsgs accumulates non-fatal advisories produced during Load
	// (deprecations, transitional behaviors, etc.). main surfaces them
	// through the configured logger after TUI/log setup, so they don't
	// race the TUI taking over stdout/stderr.
	WarnMsgs []string
}

// StartupConfig holds the sections consumed only during server bootstrap.
// After the server is up and the matcher is built, this can be discarded.
type StartupConfig struct {
	App    AppOptions
	Policy PolicyOptions
}

// RuntimeConfig holds the sections accessed on the request hot path.
// Handlers take a pointer to RuntimeConfig (not the individual *XOptions)
// so adding a new section doesn't require touching every signature, and
// rule overrides can swap the whole RuntimeConfig in a single assignment.
type RuntimeConfig struct {
	Conn  ConnOptions  `json:"conn"`
	DNS   DNSOptions   `json:"dns"`
	HTTPS HTTPSOptions `json:"https"`
	UDP   UDPOptions   `json:"udp"`
}

func (c *Config) UnmarshalTOML(data any) (err error) {
	m, ok := data.(map[string]any)
	if !ok {
		return fmt.Errorf("non-table type config file")
	}

	if app := findStructFrom[AppOptions](m, "app", &err); app != nil {
		c.Startup.App = *app
	}
	if conn := findStructFrom[ConnOptions](m, "connection", &err); conn != nil {
		c.Runtime.Conn = *conn
	}
	if dns := findStructFrom[DNSOptions](m, "dns", &err); dns != nil {
		c.Runtime.DNS = *dns
	}
	if https := findStructFrom[HTTPSOptions](m, "https", &err); https != nil {
		c.Runtime.HTTPS = *https
	}
	if udp := findStructFrom[UDPOptions](m, "udp", &err); udp != nil {
		c.Runtime.UDP = *udp
	}
	if policy := findStructFrom[PolicyOptions](m, "policy", &err); policy != nil {
		c.Startup.Policy = *policy
	}

	if policyMap, ok := m["policy"].(map[string]any); ok {
		if _, hasTemplate := policyMap["template"]; hasTemplate {
			c.WarnMsgs = append(
				c.WarnMsgs,
				"'policy.template' is deprecated and ignored; move template fields to top-level [app]/[connection]/[dns]/[https]/[udp] sections",
			)
		}
	}

	return
}

func (c *Config) ShouldEnablePcap() bool {
	if c.Runtime.HTTPS.FakeCount > 0 {
		return true
	}
	if c.Runtime.UDP.FakeCount > 0 {
		return true
	}
	for _, r := range c.Startup.Policy.Overrides {
		if r.Runtime.HTTPS.FakeCount > 0 {
			return true
		}
		if r.Runtime.UDP.FakeCount > 0 {
			return true
		}
	}
	return false
}

// Finalize applies defaults that depend on other fields (e.g. ListenAddr
// per Mode). Called after defaults+TOML+CLI layers are merged, before
// Validate. Rule resolution is handled separately by Load via
// resolveRules so PolicyOptions doesn't need to carry load-time scratch
// state into the runtime config.
func (c *Config) Finalize() error {
	if c.Startup.App.ListenAddr.IP == nil && c.Startup.App.ListenAddr.Port == 0 {
		port := 8080
		if c.Startup.App.Mode == AppModeSOCKS5 {
			port = 1080
		}
		c.Startup.App.ListenAddr = net.TCPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: port,
		}
	}
	return nil
}
