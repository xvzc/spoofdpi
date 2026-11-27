//go:build !darwin && !freebsd && !linux

package netutil

import "syscall"

// DisableAutoFlowLabel does nothing where spoofdpi sends no fake packets.
func DisableAutoFlowLabel(string, syscall.RawConn) error { return nil }
