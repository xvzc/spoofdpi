//go:build freebsd

package sysinfo

import (
	"encoding/hex"
	"fmt"

	"golang.org/x/sys/unix"
)

// bootIDSize is the size of kern.boot_id, a random 128-bit identifier.
const bootIDSize = 16

// BootID returns an identifier that the kernel picks anew at every boot. It
// returns an error wrapping ErrBootIDUnsupported when the kernel has no
// kern.boot_id or it cannot be read.
func BootID() (string, error) {
	raw, err := unix.SysctlRaw("kern.boot_id")
	if err != nil {
		return "", fmt.Errorf("%w: kern.boot_id: %w", ErrBootIDUnsupported, err)
	}
	if len(raw) != bootIDSize {
		return "", fmt.Errorf(
			"%w: kern.boot_id has %d bytes",
			ErrBootIDUnsupported,
			len(raw),
		)
	}
	return hex.EncodeToString(raw), nil
}
