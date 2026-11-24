//go:build e2e && darwin

package e2e

import (
	"slices"
	"strings"
)

// snapshot returns the network state that a TUN run must restore.
func snapshot() string {
	var b strings.Builder
	for _, family := range []string{"inet", "inet6"} {
		b.WriteString("### netstat -rn -f " + family + "\n")
		b.WriteString(stripRouteColumns(output("netstat", "-rn", "-f", family)))
	}
	b.WriteString("### ifconfig -l\n" + interfaceNames())
	return b.String()
}

// tunIface returns the TUN interface, or "" while it does not exist yet. The
// utun name is not fixed: it is the utun that the snapshot did not list, or
// the interface of the 0/1 route that spoofdpi adds.
func tunIface(before string) string {
	known := strings.Split(before, "\n")
	for _, name := range strings.Fields(output("ifconfig", "-l")) {
		if strings.HasPrefix(name, "utun") && !slices.Contains(known, name) {
			return name
		}
	}
	for _, line := range strings.Split(output("netstat", "-rn", "-f", "inet"), "\n") {
		if f := strings.Fields(line); len(f) >= 4 && f[0] == "0/1" {
			return f[3]
		}
	}
	return ""
}
