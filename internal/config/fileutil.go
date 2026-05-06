package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const filePrefix = "file:"

// resolveEntries expands file: entries into their file contents.
// Lines starting with '#' and empty lines are skipped.
// Other entries are returned as-is.
// Missing files emit a warning via AddWarnMsg instead of returning an
// error; other I/O failures (e.g. permission denied) still return an error.
// configDir is used to resolve relative paths; pass "" to use CWD.
func resolveEntries(entries []string, configDir string) ([]string, error) {
	var result []string
	for _, e := range entries {
		if !strings.HasPrefix(e, filePrefix) {
			result = append(result, e)
			continue
		}
		path := expandPath(e[len(filePrefix):], configDir)
		lines, err := readLines(path)
		if err != nil {
			if os.IsNotExist(err) {
				AddWarnMsg(fmt.Sprintf("file %q not found, skipping", path))
				continue
			}
			return nil, fmt.Errorf("failed to load %q: %w", path, err)
		}
		result = append(result, lines...)
	}
	return result, nil
}

// expandPath expands $ENV variables and leading ~ in a path.
// Relative paths are resolved against configDir; pass "" to use CWD.
func expandPath(p string, configDir string) string {
	p = os.ExpandEnv(p)
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			p = filepath.Join(home, p[2:])
		}
	} else if configDir != "" && !filepath.IsAbs(p) {
		p = filepath.Join(configDir, p)
	}
	return p
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines, scanner.Err()
}
