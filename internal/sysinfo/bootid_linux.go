//go:build linux

package sysinfo

import (
	"os"
	"strings"
)

// BootID returns an identifier that the kernel picks anew at every boot.
func BootID() (string, error) {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}
