//go:build darwin

package sysinfo

import "golang.org/x/sys/unix"

// BootID returns an identifier that the kernel picks anew at every boot.
func BootID() (string, error) {
	return unix.Sysctl("kern.bootsessionuuid")
}
