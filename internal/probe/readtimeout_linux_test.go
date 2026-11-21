//go:build linux

package probe

import "golang.org/x/sys/unix"

// errReadTimeout is the error a capture handle's read returns when its
// read timeout expires.
var errReadTimeout error = unix.EAGAIN
