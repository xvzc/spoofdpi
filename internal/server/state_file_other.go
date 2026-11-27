//go:build !darwin && !linux && !freebsd

package server

import "os"

// openStateFile opens the state file at path for reading. These platforms
// have no state files, so it checks nothing.
func openStateFile(path string, _ bool) (*os.File, error) {
	return os.Open(path)
}
