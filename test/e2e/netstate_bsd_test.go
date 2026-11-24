//go:build e2e && (darwin || freebsd)

package e2e

import (
	"os/exec"
	"slices"
	"sort"
	"strings"
)

// physicalIface returns the interface of the IPv4 default route, read with the
// OS's own route command rather than spoofdpi's route code.
func physicalIface() string {
	for _, line := range strings.Split(output("route", "-n", "get", "default"), "\n") {
		if f := strings.Fields(line); len(f) == 2 && f[0] == "interface:" {
			return f[1]
		}
	}
	return ""
}

// ifaceExists reports whether the interface is present.
func ifaceExists(name string) bool {
	return exec.Command("ifconfig", name).Run() == nil
}

// interfaceNames lists the interface names, one per line, sorted.
func interfaceNames() string {
	names := strings.Fields(output("ifconfig", "-l"))
	sort.Strings(names)
	return strings.Join(names, "\n") + "\n"
}

// stripRouteColumns keeps only the Destination, Gateway, Flags and Netif
// columns of a "netstat -rn" table. The other columns (use counters, MTU,
// next-hop ids, Expire) change without the routes changing, which would make
// an unchanged system diff dirty. Columns are located by their header, since
// darwin and FreeBSD order them differently.
func stripRouteColumns(table string) string {
	var out strings.Builder
	var cols []int
	for _, line := range strings.Split(strings.TrimRight(table, "\n"), "\n") {
		fields := strings.Fields(line)
		if header := routeColumns(fields); header != nil {
			cols = header
		}
		if cols == nil || len(fields) <= slices.Max(cols) {
			out.WriteString(line + "\n")
			continue
		}
		kept := make([]string, len(cols))
		for i, c := range cols {
			kept[i] = fields[c]
		}
		out.WriteString(strings.Join(kept, " ") + "\n")
	}
	return out.String()
}

// routeColumns returns the indexes of Destination, Gateway, Flags and Netif in
// a header row, or nil when fields is not one.
func routeColumns(fields []string) []int {
	index := map[string]int{}
	for i, name := range fields {
		index[name] = i
	}
	cols := make([]int, 0, 4)
	for _, name := range []string{"Destination", "Gateway", "Flags", "Netif"} {
		i, ok := index[name]
		if !ok {
			return nil
		}
		cols = append(cols, i)
	}
	return cols
}
