package config

import (
	"fmt"
	"os"
	"path"
	"path/filepath"

	"github.com/urfave/cli/v3"
)

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

	rules, err := resolveRules(rawRules, cfg.Runtime)
	if err != nil {
		return nil, "", err
	}
	cfg.Startup.Rules = rules

	if err := cfg.Validate(); err != nil {
		return nil, "", err
	}

	return cfg, configPath, nil
}

// loadTOML resolves the TOML config path (custom --config flag, env var,
// or one of the default locations), then decodes it onto cfg if found.
// The decode-into-defaults trick preserves cfg's pre-populated values
// for any TOML key that's absent. Raw [[rules]] / [[policy.overrides]]
// entries are extracted from the same decoded map so no second file read
// is needed. Returns the path of the decoded file (or "" if none was
// loaded) and the captured raw rules.
func loadTOML(cmd *cli.Command, cfg *Config) (string, []map[string]any, error) {
	if cmd.Bool("clean") {
		return "", nil, nil
	}

	const configFilename = "spoofdpi.toml"
	configDirs := []string{
		path.Join(string(os.PathSeparator), "etc", configFilename),
		path.Join(os.Getenv("XDG_CONFIG_HOME"), "spoofdpi", configFilename),
		path.Join(determineRealHome(), ".config", "spoofdpi", configFilename),
	}

	configPath, err := searchTomlFile(cmd.String("config"), configDirs)
	if err != nil {
		return "", nil, err
	}
	if configPath == "" {
		return "", nil, nil
	}

	m, err := fromTomlFile(configPath, cfg)
	if err != nil {
		return "", nil, fmt.Errorf("error parsing '%s': %w", configPath, err)
	}

	return configPath, rulesFromMap(m), nil
}

// rulesFromMap extracts raw [[rules]] and deprecated [[policy.overrides]]
// entries from an already-decoded TOML map. Using the deprecated key emits
// a warning.
func rulesFromMap(m map[string]any) []map[string]any {
	var rules []map[string]any
	if r, ok := m["rules"].([]map[string]any); ok {
		rules = append(rules, r...)
	}
	if policy, ok := m["policy"].(map[string]any); ok {
		if overrides, ok := policy["overrides"].([]map[string]any); ok {
			AddWarnMsg("'[[policy.overrides]]' is deprecated; rename to '[[rules]]'")
			rules = append(rules, overrides...)
		}
	}
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
			Config:   base,
		}

		// Override semantics: https.skip is intentionally NOT inherited
		// from base. Rules always start with skip=false; only the
		// rule's own TOML can set it to true. This way a global
		// https.skip=true on the static config can leave non-matched
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
		if v, ok := item["match"]; ok {
			r.Match = &MatchAttrs{} //exhaustruct:enforce
			if err := r.Match.UnmarshalTOML(v); err != nil {
				return nil, fmt.Errorf("rule %d: match: %w", i, err)
			}
		}
		if v, ok := item["dns"]; ok {
			if err := r.Config.DNS.UnmarshalTOML(v); err != nil {
				return nil, fmt.Errorf("rule %d: dns: %w", i, err)
			}
		}
		if v, ok := item["https"]; ok {
			if err := r.Config.HTTPS.UnmarshalTOML(v); err != nil {
				return nil, fmt.Errorf("rule %d: https: %w", i, err)
			}
		}
		if v, ok := item["udp"]; ok {
			if err := r.Config.UDP.UnmarshalTOML(v); err != nil {
				return nil, fmt.Errorf("rule %d: udp: %w", i, err)
			}
		}
		if v, ok := item["connection"]; ok {
			if err := r.Config.Conn.UnmarshalTOML(v); err != nil {
				return nil, fmt.Errorf("rule %d: connection: %w", i, err)
			}
		}

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
