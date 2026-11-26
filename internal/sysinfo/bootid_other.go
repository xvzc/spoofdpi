//go:build !linux && !darwin && !freebsd

package sysinfo

// BootID returns ErrBootIDUnsupported: this OS has no boot identifier.
func BootID() (string, error) {
	return "", ErrBootIDUnsupported
}
