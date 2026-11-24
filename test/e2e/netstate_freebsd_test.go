//go:build e2e && freebsd

package e2e

import (
	"strconv"
	"strings"
)

// snapshot returns the network state that a TUN run must restore: the routing
// table of every FIB, and the interface names.
func snapshot() string {
	fibs := 1
	if n, err := strconv.Atoi(
		strings.TrimSpace(output("sysctl", "-n", "net.fibs")),
	); err == nil {
		fibs = n
	}
	var b strings.Builder
	for fib := range fibs {
		n := strconv.Itoa(fib)
		b.WriteString("### setfib " + n + " netstat -rn\n")
		b.WriteString(stripRouteColumns(output("setfib", n, "netstat", "-rn")))
	}
	b.WriteString("### ifconfig -l\n" + interfaceNames())
	return b.String()
}

// tunIface returns the TUN interface, or "" while it does not exist yet.
func tunIface(string) string {
	if ifaceExists("tun-spoofdpi") {
		return "tun-spoofdpi"
	}
	return ""
}
