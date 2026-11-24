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
	// IPv6 is the ipv6 option of the connection: the rule's own value, else
	// the global one (AppOptions.IPv6), which Finalize copies here.
	IPv6 bool `json:"ipv6"`
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

// NeedsTCPStack reports whether any TCP fake-packet feature is enabled —
// either in the base config or in any rule. The TCP raw packet IO
// (sniffer + writer) is only set up when this returns true.
func (c *Config) NeedsTCPStack() bool {
	if c.HTTPS.UsesFakes() {
		return true
	}
	for _, r := range c.Rules {
		if r.Config.HTTPS.UsesFakes() {
			return true
		}
	}
	return false
}

// NeedsUDPStack is the UDP counterpart of NeedsTCPStack.
func (c *Config) NeedsUDPStack() bool {
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

// NeedsNetworkStack reports whether the TCP or UDP network stack (raw
// packet capture and injection) is needed.
func (c *Config) NeedsNetworkStack() bool {
	return c.NeedsTCPStack() || c.NeedsUDPStack()
}

// IPv6Enabled reports whether IPv6 is enabled: by the global ipv6 option,
// or, outside TUN mode, by any rule. TUN mode ignores the rules' ipv6, as
// the OS and the applications choose the address family there.
func (c *Config) IPv6Enabled() bool {
	if c.App.IPv6 {
		return true
	}
	if c.App.Mode == AppModeTUN {
		return false
	}
	for _, r := range c.Rules {
		if r.Config.IPv6 {
			return true
		}
	}
	return false
}

// DisableIPv6 turns IPv6 off for this run, as if the ipv6 option were off
// everywhere: the global option and the ipv6 that the base config and every
// rule apply become false, and their DNS record types follow, as Finalize
// and resolveRules derive them. A rule's own ipv6 (Rule.IPv6) is kept, so
// a rule that sets ipv6 = false still keeps its connections on IPv4.
func (c *Config) DisableIPv6() {
	c.App.IPv6 = false
	c.IPv6 = false
	c.DNS.QType = dnsQueryType(c.IPv6)
	for i := range c.Rules {
		r := &c.Rules[i].Config
		r.IPv6 = false
		r.DNS.QType = dnsQueryType(r.IPv6)
	}
}

// NeedsRoute reports whether the IPv4 egress must be discovered at
// startup: packet capture runs on its interface and fake packets follow
// it, and TUN mode routes its own traffic out of the TUN through it. The
// egress needs no gateway.
func (c *Config) NeedsRoute() bool {
	return c.NeedsNetworkStack() || c.App.Mode == AppModeTUN
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

	// Rules are resolved from the base RuntimeConfig after Finalize, so
	// they inherit the global value unless they set their own.
	c.IPv6 = c.App.IPv6
	c.DNS.QType = dnsQueryType(c.IPv6)
	if c.App.IPv6 {
		AddWarnMsg("'ipv6' is an experimental feature")
	}

	return nil
}
