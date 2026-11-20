package config

import (
	"fmt"
	"net"
)

// Config is the fully-loaded configuration.
//
//   - App is read once at boot (logger setup, mode selection, network
//     setup) and is not needed at request time.
//   - Rules holds the fully-resolved per-rule configurations. Populated by
//     Load.resolveRules (in load.go) after defaults+TOML+CLI are merged, so
//     each rule's Config is pre-filled from the base RuntimeConfig and
//     consumers can use rule.Config.X directly without re-merging at
//     request time.
//   - The embedded RuntimeConfig is the base per-request configuration. Its
//     sections are promoted, so they are accessed as cfg.Conn, cfg.HTTPS, etc.
type Config struct {
	App   AppOptions
	Rules []Rule
	RuntimeConfig
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

	if v, ok := m["app"]; ok && err == nil {
		err = c.App.UnmarshalTOML(v)
	}
	if v, ok := m["connection"]; ok && err == nil {
		err = c.Conn.UnmarshalTOML(v)
	}
	if v, ok := m["dns"]; ok && err == nil {
		err = c.DNS.UnmarshalTOML(v)
	}
	// [https] is the deprecated name of [tls]. When [tls] is present,
	// [https] is ignored entirely.
	//
	// TODO(deprecated): [https] was renamed to [tls] after v1.6.0. Remove
	// the [https] fallback together with the rule 'https' key (load.go),
	// the --https-* flags (cli.go) and the notes in docs/user-guide/tls.md
	// and rules.md.
	if v, ok := m["tls"]; ok && err == nil {
		if _, dup := m["https"]; dup {
			AddWarnMsg("'[https]' is ignored because '[tls]' is set")
		}
		err = c.HTTPS.UnmarshalTOML(v)
	} else if v, ok := m["https"]; ok && err == nil {
		AddWarnMsg("'[https]' is deprecated; rename to '[tls]'")
		err = c.HTTPS.UnmarshalTOML(v)
	}
	if v, ok := m["udp"]; ok && err == nil {
		err = c.UDP.UnmarshalTOML(v)
	}

	return
}

// NeedsPcapTCP reports whether any TCP fake-packet feature is enabled —
// either in the base config or in any rule. The TCP raw packet IO
// (sniffer + writer) is only set up when this returns true.
func (c *Config) NeedsPcapTCP() bool {
	if c.HTTPS.FakePreflight > 0 {
		return true
	}
	for _, r := range c.Rules {
		if r.Config.HTTPS.FakePreflight > 0 {
			return true
		}
	}
	return false
}

// NeedsPcapUDP is the UDP counterpart of NeedsPcapTCP.
func (c *Config) NeedsPcapUDP() bool {
	if c.UDP.FakePreflight > 0 {
		return true
	}
	for _, r := range c.Rules {
		if r.Config.UDP.FakePreflight > 0 {
			return true
		}
	}
	return false
}

// NeedsPcap reports whether any raw packet capture is needed.
func (c *Config) NeedsPcap() bool {
	return c.NeedsPcapTCP() || c.NeedsPcapUDP()
}

// NeedsRoute reports whether the default route must be discovered at
// startup: raw packet capture needs the gateway, and TUN mode routes
// traffic through it.
func (c *Config) NeedsRoute() bool {
	return c.NeedsPcap() || c.App.Mode == AppModeTUN
}

// Finalize applies defaults that depend on other fields (e.g. ListenAddr
// per Mode). Called after defaults+TOML+CLI layers are merged, before
// Validate. Rule resolution is handled separately by Load via
// resolveRules so Config doesn't need to carry load-time scratch
// state into the runtime config.
func (c *Config) Finalize() error {
	if c.App.ListenAddr.IP == nil && c.App.ListenAddr.Port == 0 {
		port := 8080
		if c.App.Mode == AppModeSOCKS5 {
			port = 1080
		}
		c.App.ListenAddr = net.TCPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: port,
		}
	}

	switch c.App.Mode {
	case AppModeSOCKS5:
		AddWarnMsg("'socks5' mode is an experimental feature")
	case AppModeTUN:
		AddWarnMsg("'tun' mode is an experimental feature")
	}

	return nil
}
