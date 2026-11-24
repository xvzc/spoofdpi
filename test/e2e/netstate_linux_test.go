//go:build e2e && linux

package e2e

import (
	"os/exec"
	"regexp"
	"strings"
)

// expires is the "expires <time>" attribute of RA and cached routes, which
// counts down and would make an unchanged system diff dirty.
var expires = regexp.MustCompile(` expires \S*`)

// physicalIface returns the interface of the IPv4 default route, read with the
// OS's own ip command rather than spoofdpi's route code.
func physicalIface() string {
	f := strings.Fields(output("ip", "-4", "route", "get", "1.1.1.1"))
	for i := 0; i+1 < len(f); i++ {
		if f[i] == "dev" {
			return f[i+1]
		}
	}
	return ""
}

// snapshot returns the network state that a TUN run must restore. Only link
// names are listed, since link counters change all the time.
func snapshot() string {
	var b strings.Builder
	for _, cmd := range [][]string{
		{"ip", "route", "show", "table", "all"},
		{"ip", "-6", "route", "show", "table", "all"},
		{"ip", "rule"},
		{"ip", "-6", "rule"},
	} {
		b.WriteString("### " + strings.Join(cmd, " ") + "\n")
		b.WriteString(expires.ReplaceAllString(output(cmd[0], cmd[1:]...), ""))
	}
	b.WriteString("### links\n")
	for _, line := range strings.Split(output("ip", "-o", "link", "show"), "\n") {
		if f := strings.Fields(line); len(f) >= 2 {
			b.WriteString(f[1] + "\n")
		}
	}
	return b.String()
}

// ifaceExists reports whether the interface is present.
func ifaceExists(name string) bool {
	return exec.Command("ip", "link", "show", "dev", name).Run() == nil
}

// tunIface returns the TUN interface, or "" while it does not exist yet.
func tunIface(string) string {
	if ifaceExists("tun-spoofdpi") {
		return "tun-spoofdpi"
	}
	return ""
}
