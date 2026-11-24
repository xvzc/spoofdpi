//go:build e2e && (darwin || freebsd)

package e2e

import (
	"os/exec"
	"slices"
	"sort"
	"strings"
	"testing"
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
//
// It also drops the rows that the kernel adds and changes on its own as
// traffic flows: darwin's link-layer entries (flag L: the ARP and NDP
// neighbours) and cloned host routes (flag W). spoofdpi adds neither, so a
// leftover route of its own still shows.
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
		if strings.ContainsAny(fields[cols[2]], "LW") {
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

func TestStripRouteColumns(t *testing.T) {
	table := `Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            172.20.0.1         UGScg                 en0
0/1                utun7              UScg                utun7
100.100.100.100    link#21            UHWIi               utun6
172.20.0.209       3a:72:38:3d:9d:8f  UHLWIi                en0   1200
`
	want := `Routing tables

Internet:
Destination Gateway Flags Netif
default 172.20.0.1 UGScg en0
0/1 utun7 UScg utun7
`
	if got := stripRouteColumns(table); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}
