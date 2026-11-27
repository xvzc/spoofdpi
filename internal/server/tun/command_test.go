//go:build darwin || linux || freebsd

package tun

import (
	"strings"

	"github.com/xvzc/spoofdpi/internal/server"
)

// command returns the CommandAction of the command line s, split at spaces.
func command(s string) server.CommandAction {
	return strings.Fields(s)
}
