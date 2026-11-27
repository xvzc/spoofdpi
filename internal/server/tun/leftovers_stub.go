//go:build !darwin && !linux && !freebsd

package tun

import "github.com/rs/zerolog"

// CleanLeftovers does nothing: TUN mode is not supported here.
func CleanLeftovers(zerolog.Logger) {}

// CheckLeftoversAfterReset does nothing: TUN mode is not supported here.
func CheckLeftoversAfterReset(zerolog.Logger) {}
