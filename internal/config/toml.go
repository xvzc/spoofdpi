package config

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
	"github.com/samber/lo"
)

// fromTomlFile decodes the TOML at `dir` into a map, then feeds it to
// cfg.UnmarshalTOML. Pre-existing values in cfg are preserved for any field
// absent from the TOML. The decoded map is returned so callers can extract
// additional data (e.g. raw rules) without a second file read.
func fromTomlFile(dir string, cfg *Config) (map[string]any, error) {
	_ = os.Setenv("BURNTSUSHI_TOML_110", "1") // allow new lines in toml file

	var m map[string]any
	if _, err := toml.DecodeFile(dir, &m); err != nil {
		return nil, err
	}
	if err := cfg.UnmarshalTOML(m); err != nil {
		return nil, err
	}
	return m, nil
}

func searchTomlFile(customDir string, lookupDirs []string) (string, error) {
	if customDir != "" {
		_, err := os.Stat(customDir)
		if err != nil { // Path exists
			return "", fmt.Errorf("no such file: %s", customDir)
		} else {
			return customDir, nil
		}
	}

	for _, p := range lookupDirs {
		if p == "" {
			continue
		}

		if _, err := os.Stat(p); err == nil { // Path exists
			return p, nil
		}
	}

	// Don't care even if config files are not found in lookupDirs
	return "", nil
}

func findFrom[T any](
	data map[string]any,
	key string,
	parser func(any) (T, error),
	err *error,
) *T {
	if err != nil && *err != nil {
		return nil
	}

	anyVal, ok := data[key]
	if !ok {
		return nil
	}

	val, parseErr := parser(anyVal)
	if parseErr != nil {
		*err = fmt.Errorf("field %q: %w", key, parseErr)
		return nil
	}

	return lo.ToPtr(val)
}

func findStructFrom[T any, PT interface {
	*T
	toml.Unmarshaler
}](m map[string]any, key string, errPtr *error) *T {
	if errPtr != nil && *errPtr != nil {
		return nil
	}

	val, ok := m[key]
	if !ok {
		return nil
	}

	var item T
	if err := PT(&item).UnmarshalTOML(val); err != nil {
		*errPtr = fmt.Errorf("failed to decode '%s': %w", key, err)
		return nil
	}

	return &item
}

func findStructSliceFrom[T any, PT interface {
	*T
	toml.Unmarshaler
}](m map[string]any, key string, errPtr *error) []T {
	if errPtr != nil && *errPtr != nil {
		return nil
	}

	val, ok := m[key]
	if !ok {
		return nil
	}

	rawList, ok := val.([]any)
	if !ok {
		if mapList, ok := val.([]map[string]any); ok {
			rawList = make([]any, len(mapList))
			for i, v := range mapList {
				rawList[i] = v
			}
		} else {
			*errPtr = fmt.Errorf("field '%s' is not a list", key)
			return nil
		}
	}

	res := make([]T, 0, len(rawList))
	for i, raw := range rawList {
		var item T
		if err := PT(&item).UnmarshalTOML(raw); err != nil {
			*errPtr = fmt.Errorf("failed to decode '%s' item [%d]: %w", key, i, err)
			return nil
		}
		res = append(res, item)
	}

	return res
}

func findSliceFrom[T any](
	data map[string]any,
	key string,
	elementParser func(any) (T, error),
	err *error,
) []T {
	if err != nil && *err != nil {
		return nil
	}

	val, ok := data[key]
	if !ok {
		return nil
	}

	rawList, ok := val.([]any)
	if !ok {
		if typedList, ok := val.([]T); ok {
			return typedList
		}
		*err = fmt.Errorf("field %q: expected list, got %T", key, val)
		return nil
	}

	result := make([]T, 0, len(rawList))

	for i, rawItem := range rawList {
		parsedItem, parseErr := elementParser(rawItem)
		if parseErr != nil {
			*err = fmt.Errorf("field %q[%d]: %w", key, i, parseErr)
			return nil
		}
		result = append(result, parsedItem)
	}

	return result
}
