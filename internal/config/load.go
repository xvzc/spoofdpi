package config

import (
	"fmt"
	"os"
	"path"
	"path/filepath"

	"github.com/urfave/cli/v3"
)

// configNotFoundMsg is the warning Load adds when it searches the default
// locations and finds no config file.
const configNotFoundMsg = "config file not found"

// Load assembles the effective Config from three sources, in precedence
// order: defaults → TOML → CLI flags. After all layers are merged it
// runs Finalize (cross-field defaults), resolveRules (eager-resolve
// rules on top of the finalized base RuntimeConfig), and Validate
// (semantic checks). Returns the resolved Config and the path of the
// TOML file that was used (or "" if none).
//
// cliOverrides is the slice of closures appended by Flag.Action
// callbacks during cmd.Run — one per flag the user actually set.
// Applying them after loadTOML is what makes CLI win over TOML.
func Load(cmd *cli.Command, cliOverrides []func(*Config)) (*Config, string, error) {
	cfg := DefaultConfig()

	configPath, rawRules, err := loadTOML(cmd, cfg)
	if err != nil {
		return nil, "", err
	}

	for _, apply := range cliOverrides {
		apply(cfg)
	}

	if err := cfg.Finalize(); err != nil {
		return nil, "", err
	}

	configDir := filepath.Dir(configPath)
	for i, rule := range rawRules {
		if v, ok := rule["match"]; ok {
			if err := expandFileMatchList(v, i, configDir); err != nil {
				return nil, "", err
			}
		}
	}

	rules, err := resolveRules(rawRules, cfg.RuntimeConfig)
	if err != nil {
		return nil, "", err
	}
	cfg.Rules = rules

	if err := cfg.Validate(); err != nil {
		return nil, "", err
	}

	return cfg, configPath, nil
}

// loadTOML resolves the TOML config path (custom --config flag, env var,
// or one of the default locations), then decodes it onto cfg if found.
// The decode-into-defaults trick preserves cfg's pre-populated values
// for any TOML key that's absent. Raw [[rules]] entries are extracted
// from the same decoded map so no second file read is needed. Returns the
// path of the decoded file (or "" if none was loaded) and the captured raw
// rules. A search that finds no file adds a warning; --clean, which skips
// the search, does not.
func loadTOML(cmd *cli.Command, cfg *Config) (string, []map[string]any, error) {
	if cmd.Bool("clean") {
		return "", nil, nil
	}

	configPath, err := findConfigFile(cmd.String("config"))
	if err != nil {
		return "", nil, err
	}
	if configPath == "" {
		// livetest reads this message to report that spoofdpi found no
		// config file (internal/livetest/case.go).
		AddWarnMsg(configNotFoundMsg)
		AddWarnMsg(
			" please try 'sudo -E spoofdpi' if you expect a configuration to be loaded",
		)
		return "", nil, nil
	}

	m, err := fromTomlFile(configPath, cfg)
	if err != nil {
		return "", nil, fmt.Errorf("error parsing '%s': %w", configPath, err)
	}

	return configPath, rulesFromMap(m), nil
}

// LoadDNS builds DNSOptions from the defaults overlaid with the [dns]
// section of the TOML config, found the same way as by Load: explicitPath
// if not empty, otherwise the first of the default locations that exists.
// All other sections, including [[rules]], are ignored and not validated.
// Returns the options and the path of the file used ("" if none).
func LoadDNS(explicitPath string) (DNSOptions, string, error) {
	opts := DefaultConfig().DNS

	configPath, err := findConfigFile(explicitPath)
	if err != nil {
		return DNSOptions{}, "", err
	}
	if configPath == "" {
		return opts, "", nil
	}

	m, err := decodeTomlFile(configPath)
	if err == nil {
		if v, ok := m["dns"]; ok {
			err = opts.UnmarshalTOML(v)
		}
	}
	if err != nil {
		return DNSOptions{}, "", fmt.Errorf("error parsing '%s': %w", configPath, err)
	}

	return opts, configPath, nil
}

// findConfigFile returns explicitPath if it is not empty (an error if it
// does not exist), otherwise the first default TOML config location that
// exists, or "" if there is none.
func findConfigFile(explicitPath string) (string, error) {
	const configFilename = "spoofdpi.toml"
	configDirs := []string{
		path.Join(string(os.PathSeparator), "etc", configFilename),
		path.Join(os.Getenv("XDG_CONFIG_HOME"), "spoofdpi", configFilename),
		path.Join(determineRealHome(), ".config", "spoofdpi", configFilename),
	}

	return searchTomlFile(explicitPath, configDirs)
}

// rulesFromMap extracts raw [[rules]] entries from an already-decoded TOML
// map.
func rulesFromMap(m map[string]any) []map[string]any {
	rules, _ := m["rules"].([]map[string]any)
	return rules
}

// resolveRules expands raw rule tables into a slice of fully-populated
// Rules. Each rule's Config is pre-filled from the finalized base
// RuntimeConfig and then overlaid with whatever the rule's own TOML
// supplies. Because each section's UnmarshalTOML preserves existing
// values for absent keys, sparse rule overrides inherit unset fields
// from base — that's the point of doing this after Finalize rather
// than at decode time.
func resolveRules(raw []map[string]any, base RuntimeConfig) ([]Rule, error) {
	rules := make([]Rule, 0, len(raw))
	for i, item := range raw {
		r := Rule{ //exhaustruct:enforce
			Name:     "",
			Priority: 0,
			Block:    false,
			Match:    nil,
			IPv6:     nil,
			Config:   base,
		}

		// Override semantics: tls.skip is intentionally NOT inherited
		// from base. Rules always start with skip=false; only the
		// rule's own TOML can set it to true. This way a global
		// tls.skip=true on the static config can leave non-matched
		// traffic alone without silently turning rules into no-ops.
		// The rule's HTTPS UnmarshalTOML below will overwrite this
		// only if the rule explicitly sets skip.
		r.Config.HTTPS.Skip = false
		r.Config.UDP.Skip = false

		if v, ok := item["name"].(string); ok {
			r.Name = v
		}
		if v, ok := item["priority"]; ok {
			pv, perr := parseIntFn[uint16](checkUint16)(v)
			if perr != nil {
				return nil, fmt.Errorf("rule %d: priority: %w", i, perr)
			}
			r.Priority = pv
		}
		if v, ok := item["block"].(bool); ok {
			r.Block = v
		}
		// Config.IPv6 already holds the global value, which a rule without
		// its own ipv6 inherits.
		if v, ok := item["ipv6"]; ok {
			ipv6, perr := parseBoolFn()(v)
			if perr != nil {
				return nil, fmt.Errorf("rule %d: ipv6: %w", i, perr)
			}
			r.IPv6 = &ipv6
			r.Config.IPv6 = ipv6
		}
		if v, ok := item["match"]; ok {
			r.Match = &MatchAttrs{} //exhaustruct:enforce
			if err := r.Match.UnmarshalTOML(v); err != nil {
				return nil, fmt.Errorf("rule %d: match: %w", i, err)
			}
		}
		if v, ok := item["dns"]; ok {
			if err := unmarshalScoped(i, r.Config.DNS.UnmarshalTOML, v); err != nil {
				return nil, fmt.Errorf("rule %d: dns: %w", i, err)
			}
		}
		// 'https' is the deprecated name of 'tls'. When 'tls' is present,
		// 'https' is ignored entirely.
		//
		// TODO(deprecated): renamed to 'tls' after v1.6.0; remove with the
		// [https] fallback in Config.UnmarshalTOML (config.go).
		if v, ok := item["tls"]; ok {
			if _, dup := item["https"]; dup {
				AddWarnMsg(fmt.Sprintf(
					"rule %d: 'https' is ignored because 'tls' is set", i,
				))
			}
			if err := unmarshalScoped(i, r.Config.HTTPS.UnmarshalTOML, v); err != nil {
				return nil, fmt.Errorf("rule %d: tls: %w", i, err)
			}
		} else if v, ok := item["https"]; ok {
			AddWarnMsg(fmt.Sprintf(
				"rule %d: 'https' is deprecated; rename to 'tls'", i,
			))
			if err := unmarshalScoped(i, r.Config.HTTPS.UnmarshalTOML, v); err != nil {
				return nil, fmt.Errorf("rule %d: https: %w", i, err)
			}
		}
		if v, ok := item["udp"]; ok {
			if err := unmarshalScoped(i, r.Config.UDP.UnmarshalTOML, v); err != nil {
				return nil, fmt.Errorf("rule %d: udp: %w", i, err)
			}
		}
		if v, ok := item["connection"]; ok {
			if err := unmarshalScoped(i, r.Config.Conn.UnmarshalTOML, v); err != nil {
				return nil, fmt.Errorf("rule %d: connection: %w", i, err)
			}
		}
		r.Config.DNS.QType = dnsQueryType(r.Config.IPv6)

		rules = append(rules, r)
	}
	return rules, nil
}

// expandFileMatchList expands any file: entries in the domains/cidrs
// arrays of a raw match map in-place. Missing files emit a warning via
// AddWarnMsg; other I/O failures return an error.
func expandFileMatchList(v any, ruleIdx int, configDir string) error {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	for _, key := range []string{"domains", "cidrs"} {
		arr, ok := m[key].([]any)
		if !ok {
			continue
		}
		entries := make([]string, 0, len(arr))
		for _, e := range arr {
			if s, ok := e.(string); ok {
				entries = append(entries, s)
			}
		}
		expanded, err := resolveEntries(entries, configDir)
		if err != nil {
			return fmt.Errorf("rule %d: match.%s: %w", ruleIdx, key, err)
		}
		result := make([]any, len(expanded))
		for j, s := range expanded {
			result[j] = s
		}
		m[key] = result
	}
	return nil
}

// unmarshalScoped runs one section's UnmarshalTOML for rule i, prefixing
// the warnings it adds with "rule i".
func unmarshalScoped(i int, fn func(any) error, v any) error {
	return scopeWarnings(fmt.Sprintf("rule %d", i), func() error { return fn(v) })
}
