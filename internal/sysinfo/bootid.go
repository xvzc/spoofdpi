// Package sysinfo reads facts about the running system.
package sysinfo

import "errors"

// ErrBootIDUnsupported is returned by BootID on an OS that has no boot
// identifier.
var ErrBootIDUnsupported = errors.New("boot id is not supported on this OS")
