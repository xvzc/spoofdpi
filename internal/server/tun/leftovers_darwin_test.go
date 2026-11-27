//go:build darwin

package tun

import (
	"bytes"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/route"
	"golang.org/x/sys/unix"
)

// The flags of the fixtures, as `netstat -rn` shows them on macOS.
const (
	// scopedDefaultFlags is UGScIg: a static scoped default route through
	// a gateway, as `route add -ifscope en0 default 172.20.0.1` adds it.
	scopedDefaultFlags = unix.RTF_UP | unix.RTF_GATEWAY | unix.RTF_STATIC |
		unix.RTF_PRCLONING | unix.RTF_IFSCOPE | unix.RTF_GLOBAL
	// utunRouteFlags is UCS2: a tagged route through a utun.
	utunRouteFlags = unix.RTF_UP | unix.RTF_CLONING | unix.RTF_STATIC | unix.RTF_PROTO2
)

var (
	en0Gateway = netip.MustParseAddr("172.20.0.1")

	// ownScopedDefault is the scoped default route of en0 (index 11) that
	// TUN mode adds.
	ownScopedDefault = route.TableRoute{
		Dst:     netip.MustParsePrefix("0.0.0.0/0"),
		Gateway: en0Gateway,
		Index:   11,
		IfName:  "en0",
		Flags:   scopedDefaultFlags | unix.RTF_PROTO2,
	}
	// primaryDefault is the unscoped default route of en0, UGScg.
	primaryDefault = route.TableRoute{
		Dst:     netip.MustParsePrefix("0.0.0.0/0"),
		Gateway: en0Gateway,
		Index:   11,
		IfName:  "en0",
		Flags:   scopedDefaultFlags &^ unix.RTF_IFSCOPE,
	}
	// tailscaleDefault is the scoped default route of a VPN's utun6
	// (index 21), `default link#21 UCSIg utun6`.
	tailscaleDefault = route.TableRoute{
		Dst:         netip.MustParsePrefix("0.0.0.0/0"),
		GatewayLink: 21,
		Index:       21,
		IfName:      "utun6",
		Flags: unix.RTF_UP | unix.RTF_CLONING | unix.RTF_STATIC |
			unix.RTF_IFSCOPE | unix.RTF_GLOBAL,
	}
	// tailscaleRoute is a route of the VPN through utun6, UCS.
	tailscaleRoute = route.TableRoute{
		Dst:         netip.MustParsePrefix("100.64.0.0/10"),
		GatewayLink: 21,
		Index:       21,
		IfName:      "utun6",
		Flags:       unix.RTF_UP | unix.RTF_CLONING | unix.RTF_STATIC,
	}
	// clonedProto3 is a host route the kernel cloned and marked with
	// RTF_PROTO3, `172.20.0.1 link#21 UHW3I utun6`.
	clonedProto3 = route.TableRoute{
		Dst:         netip.MustParsePrefix("172.20.0.1/32"),
		GatewayLink: 21,
		Index:       21,
		IfName:      "utun6",
		Flags: unix.RTF_UP | unix.RTF_HOST | unix.RTF_WASCLONED |
			unix.RTF_PROTO3 | unix.RTF_IFSCOPE,
	}
	// liveUTUNRoute is the 0/1 route of a running instance through utun9
	// (index 30).
	liveUTUNRoute = route.TableRoute{
		Dst:         netip.MustParsePrefix("0.0.0.0/1"),
		GatewayLink: 30,
		Index:       30,
		IfName:      "utun9",
		Flags:       utunRouteFlags,
	}

	testInterfaceNames = map[int]string{1: "lo0", 11: "en0", 21: "utun6", 30: "utun9"}
)

// fakeRouteTable is a routing table of IPv4 and IPv6 routes. Deleting a
// route removes the route of the same destination and scope, as darwin
// does.
type fakeRouteTable struct {
	routes  []route.TableRoute
	deleted []route.TableRoute
	// dumpErr and deleteErr, when set, are the errors of dump and delete.
	dumpErr   error
	deleteErr error
	// beforeDelete, when set, runs at the first dump after the first one,
	// to change the table between the search and a removal.
	beforeDelete func(*fakeRouteTable)
	dumps        int
}

func (f *fakeRouteTable) table() routeTable {
	return routeTable{
		dump: func(fam netutil.Family) ([]route.TableRoute, error) {
			if f.dumpErr != nil {
				return nil, f.dumpErr
			}
			f.dumps++
			if f.dumps == 2 && f.beforeDelete != nil {
				f.beforeDelete(f)
			}
			var routes []route.TableRoute
			for _, r := range f.routes {
				if r.Dst.Addr().Is6() == (fam == netutil.FamilyV6) {
					routes = append(routes, r)
				}
			}
			return routes, nil
		},
		delete: func(r route.TableRoute) error {
			if f.deleteErr != nil {
				return f.deleteErr
			}
			f.deleted = append(f.deleted, r)
			scoped := r.Flags&unix.RTF_IFSCOPE != 0
			f.routes = slices.DeleteFunc(f.routes, func(o route.TableRoute) bool {
				oScoped := o.Flags&unix.RTF_IFSCOPE != 0
				return o.Dst == r.Dst && oScoped == scoped && (!scoped || o.Index == r.Index)
			})
			return nil
		},
		interfaceNames: func() (map[int]string, error) {
			return testInterfaceNames, nil
		},
	}
}

// logLines returns the JSON log lines in logs.
func logLines(logs *bytes.Buffer) []string {
	s := strings.TrimSpace(logs.String())
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func TestCleanLeftovers_Darwin(t *testing.T) {
	duplicate := ownScopedDefault
	duplicate.Flags &^= unix.RTF_GLOBAL
	untaggedOwnShape := ownScopedDefault
	untaggedOwnShape.Flags &^= unix.RTF_PROTO2
	wasCloned := ownScopedDefault
	wasCloned.Flags |= unix.RTF_WASCLONED
	notStatic := ownScopedDefault
	notStatic.Flags &^= unix.RTF_STATIC
	linkDefault := route.TableRoute{
		Dst:         netip.MustParsePrefix("0.0.0.0/0"),
		GatewayLink: 11,
		Index:       11,
		Flags: unix.RTF_UP | unix.RTF_STATIC | unix.RTF_PRCLONING |
			unix.RTF_IFSCOPE | unix.RTF_PROTO2,
	}
	linkOfOther := linkDefault
	linkOfOther.GatewayLink = 1
	taggedTailscaleDefault := tailscaleDefault
	taggedTailscaleDefault.Flags |= unix.RTF_PROTO2
	clonedTagged := liveUTUNRoute
	clonedTagged.Dst = netip.MustParsePrefix("1.1.1.1/32")
	clonedTagged.Flags |= unix.RTF_WASCLONED | unix.RTF_HOST
	liveIPv6Index := liveUTUNRoute
	liveIPv6Index.GatewayLink = 0
	liveIPv6Index.IfName = ""

	// system is the table of a host with a VPN, without TUN mode.
	system := []route.TableRoute{
		primaryDefault,
		tailscaleDefault,
		tailscaleRoute,
		clonedProto3,
	}

	tcs := []struct {
		name        string
		routes      []route.TableRoute
		wantDeleted []route.TableRoute
		// wantLogs are substrings of the log lines, one for each.
		wantLogs []string
	}{
		{
			name:     "nothing of spoofdpi",
			routes:   system,
			wantLogs: nil,
		},
		{
			name:        "single tagged scoped default removed",
			routes:      append(slices.Clone(system), ownScopedDefault),
			wantDeleted: []route.TableRoute{ownScopedDefault},
			wantLogs:    []string{`"level":"info"`},
		},
		{
			name:        "tagged scoped default through the interface removed",
			routes:      append(slices.Clone(system), linkDefault),
			wantDeleted: []route.TableRoute{linkDefault},
			wantLogs:    []string{`"level":"info"`},
		},
		{
			name: "live instance skips the cleanup",
			routes: append(slices.Clone(system),
				liveUTUNRoute, ownScopedDefault),
			wantLogs: []string{
				`"level":"info","route":"0.0.0.0/1 gateway link#30 index 30 (utun9)` +
					` flags 0x4901","message":"another spoofdpi instance`,
			},
		},
		{
			name:     "live instance found by the interface index of the route",
			routes:   []route.TableRoute{liveIPv6Index, ownScopedDefault},
			wantLogs: []string{`another spoofdpi instance is running`},
		},
		{
			name:        "cloned tagged route through a utun is no live instance",
			routes:      []route.TableRoute{clonedTagged, ownScopedDefault},
			wantDeleted: []route.TableRoute{ownScopedDefault},
			wantLogs:    []string{`"level":"info"`},
		},
		{
			name:   "duplicate scoped defaults warn",
			routes: []route.TableRoute{primaryDefault, ownScopedDefault, duplicate},
			wantLogs: []string{
				`"manual_command":"route -n delete -ifscope en0 default 172.20.0.1"`,
				`"manual_command":"route -n delete -ifscope en0 default 172.20.0.1"`,
			},
		},
		{
			name:     "untagged scoped default untouched",
			routes:   append(slices.Clone(system), untaggedOwnShape),
			wantLogs: nil,
		},
		{
			name:   "tagged scoped default cloned by the kernel warns",
			routes: []route.TableRoute{wasCloned},
			wantLogs: []string{
				`"level":"warn","leftover":"scoped default route 0.0.0.0/0`,
			},
		},
		{
			name:     "tagged scoped default that is not static warns",
			routes:   []route.TableRoute{notStatic},
			wantLogs: []string{`not removed automatically`},
		},
		{
			name:   "tagged scoped default through another link warns",
			routes: []route.TableRoute{linkOfOther},
			wantLogs: []string{
				`"manual_command":"route -n delete -ifscope en0 default -interface en0"`,
			},
		},
		{
			name: "tagged scoped default of a utun is a live instance",
			routes: []route.TableRoute{
				taggedTailscaleDefault, ownScopedDefault,
			},
			wantLogs: []string{`another spoofdpi instance is running`},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeRouteTable{routes: slices.Clone(tc.routes)}
			var logs bytes.Buffer

			cleanLeftovers(zerolog.New(&logs), fake.table())

			assert.Equal(t, tc.wantDeleted, fake.deleted)
			lines := logLines(&logs)
			require.Len(t, lines, len(tc.wantLogs), "logs: %s", logs.String())
			for i, want := range tc.wantLogs {
				assert.Contains(t, lines[i], want)
			}
			for _, r := range system {
				if slices.Contains(tc.routes, r) {
					assert.Contains(t, fake.routes, r, "a route of others stays")
				}
			}
		})
	}
}

func TestCleanLeftovers_Darwin_SingleRemovedLog(t *testing.T) {
	fake := &fakeRouteTable{routes: []route.TableRoute{primaryDefault, ownScopedDefault}}
	var logs bytes.Buffer

	cleanLeftovers(zerolog.New(&logs), fake.table())

	assert.Equal(t, []string{
		`{"level":"info","leftover":"scoped default route 0.0.0.0/0 gateway ` +
			`172.20.0.1 index 11 (en0) flags 0x41014803",` +
			`"message":"removed leftover network configuration"}`,
	}, logLines(&logs))
	assert.Equal(t, []route.TableRoute{primaryDefault}, fake.routes)
}

func TestCleanLeftovers_Darwin_RecheckBeforeDelete(t *testing.T) {
	tcs := []struct {
		name    string
		change  func(*fakeRouteTable)
		wantErr string
	}{
		{
			name: "an instance started",
			change: func(f *fakeRouteTable) {
				f.routes = append(f.routes, liveUTUNRoute)
			},
			wantErr: "another spoofdpi instance is running",
		},
		{
			name: "the route went away",
			change: func(f *fakeRouteTable) {
				f.routes = []route.TableRoute{primaryDefault}
			},
			wantErr: "the route changed before it could be removed",
		},
		{
			name: "the route was replaced",
			change: func(f *fakeRouteTable) {
				r := ownScopedDefault
				r.Gateway = netip.MustParseAddr("172.20.0.254")
				f.routes = []route.TableRoute{primaryDefault, r}
			},
			wantErr: "the route changed before it could be removed",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeRouteTable{
				routes:       []route.TableRoute{primaryDefault, ownScopedDefault},
				beforeDelete: tc.change,
			}
			var logs bytes.Buffer

			cleanLeftovers(zerolog.New(&logs), fake.table())

			assert.Empty(t, fake.deleted)
			lines := logLines(&logs)
			require.Len(t, lines, 1)
			assert.Contains(t, lines[0], `"level":"warn"`)
			assert.Contains(t, lines[0], tc.wantErr)
		})
	}
}

func TestCleanLeftovers_Darwin_Errors(t *testing.T) {
	t.Run("permission denied hints at root", func(t *testing.T) {
		fake := &fakeRouteTable{
			routes:    []route.TableRoute{ownScopedDefault},
			deleteErr: unix.EPERM,
		}
		var logs bytes.Buffer

		cleanLeftovers(zerolog.New(&logs), fake.table())

		lines := logLines(&logs)
		require.Len(t, lines, 1)
		assert.Contains(t, lines[0], `"level":"warn"`)
		assert.Contains(t, lines[0], "run spoofdpi as root")
		assert.Contains(t, lines[0],
			`"manual_command":"route -n delete -ifscope en0 default 172.20.0.1"`)
	})
	t.Run("dump fails", func(t *testing.T) {
		fake := &fakeRouteTable{dumpErr: errors.New("boom")}
		var logs bytes.Buffer

		cleanLeftovers(zerolog.New(&logs), fake.table())

		assert.Equal(t, []string{
			`{"level":"warn","error":"boom",` +
				`"message":"failed to look for TUN mode leftovers"}`,
		}, logLines(&logs))
	})
	t.Run("interface names fail", func(t *testing.T) {
		fake := &fakeRouteTable{routes: []route.TableRoute{ownScopedDefault}}
		table := fake.table()
		table.interfaceNames = func() (map[int]string, error) {
			return nil, errors.New("boom")
		}
		var logs bytes.Buffer

		cleanLeftovers(zerolog.New(&logs), table)

		assert.Empty(t, fake.deleted, "without names a live instance is unknown")
		assert.Len(t, logLines(&logs), 1)
	})
}

func TestCheckLeftoversAfterReset_Darwin(t *testing.T) {
	info := testInfoDarwin()
	info.Gateway = en0Gateway
	info.PhysIfaceIndex = 11
	info.IPv6Enabled = true
	info.HasIPv6Egress = true
	added := addedRoutes(buildJobs(zerolog.Nop(), info))

	// dumped returns r as the kernel dumps it.
	dumped := func(r route.TableRoute, flags int) route.TableRoute {
		r.Flags |= flags
		return r
	}
	scoped := dumped(scopedDefaultRoute(info), scopedDefaultFlags)
	utun0 := dumped(tunRoute(info, netip.MustParsePrefix("0.0.0.0/1")), utunRouteFlags)
	utun0.Index = 30
	utun6 := dumped(tunRoute(info, netip.MustParsePrefix("2000::/3")), utunRouteFlags)
	otherUTUN := utun0
	otherUTUN.GatewayLink = 21
	untaggedScoped := scoped
	untaggedScoped.Flags &^= unix.RTF_PROTO2

	tcs := []struct {
		name     string
		routes   []route.TableRoute
		wantLogs []string
	}{
		{
			name: "all restored",
			routes: []route.TableRoute{
				primaryDefault,
				tailscaleDefault,
				untaggedScoped,
				otherUTUN,
			},
		},
		{
			name:   "routes left",
			routes: []route.TableRoute{primaryDefault, utun0, scoped, utun6},
			wantLogs: []string{
				`"manual_command":"route -n delete -net 0.0.0.0/1 -interface utun9"`,
				`"manual_command":"route -n delete -ifscope en0 default 172.20.0.1"`,
				`"manual_command":"route -n delete -inet6 -net 2000::/3 -interface utun9"`,
			},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeRouteTable{routes: tc.routes}
			var logs bytes.Buffer

			checkLeftoversAfterReset(zerolog.New(&logs), fake.table(), added)

			assert.Empty(t, fake.deleted, "nothing is removed")
			lines := logLines(&logs)
			require.Len(t, lines, len(tc.wantLogs), "logs: %s", logs.String())
			for i, want := range tc.wantLogs {
				assert.Contains(t, lines[i], `"level":"warn"`)
				assert.Contains(t, lines[i], want)
			}
		})
	}
}

func TestResetScopedDefault(t *testing.T) {
	// added is the scoped default route of en0 as the job adds it.
	added := route.TableRoute{
		Dst:     ownScopedDefault.Dst,
		Gateway: en0Gateway,
		Index:   11,
		IfName:  "en0",
		Flags:   unix.RTF_PROTO2 | unix.RTF_IFSCOPE,
	}
	system := ownScopedDefault
	system.Flags &^= unix.RTF_PROTO2
	otherGateway := ownScopedDefault
	otherGateway.Gateway = netip.MustParseAddr("172.20.0.254")
	duplicate := ownScopedDefault
	duplicate.Flags &^= unix.RTF_GLOBAL

	tcs := []struct {
		name        string
		routes      []route.TableRoute
		wantDeleted []route.TableRoute
		wantWarn    bool
	}{
		{
			name:        "still this run's",
			routes:      []route.TableRoute{primaryDefault, ownScopedDefault},
			wantDeleted: []route.TableRoute{added},
		},
		{
			name:     "replaced by the system's",
			routes:   []route.TableRoute{primaryDefault, system},
			wantWarn: true,
		},
		{
			name:     "replaced through another gateway",
			routes:   []route.TableRoute{otherGateway},
			wantWarn: true,
		},
		{
			name:     "gone",
			routes:   []route.TableRoute{primaryDefault},
			wantWarn: true,
		},
		{
			name:     "duplicate",
			routes:   []route.TableRoute{ownScopedDefault, duplicate},
			wantWarn: true,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeRouteTable{routes: slices.Clone(tc.routes)}
			var logs bytes.Buffer

			err := resetScopedDefault(zerolog.New(&logs), fake.table(), added)

			require.NoError(t, err)
			assert.Equal(t, tc.wantDeleted, fake.deleted)
			if tc.wantWarn {
				assert.Contains(t, logs.String(), `"level":"warn"`)
				assert.Contains(t, logs.String(), "keeping it")
			} else {
				assert.Empty(t, logs.String())
			}
		})
	}

	t.Run("dump fails", func(t *testing.T) {
		fake := &fakeRouteTable{dumpErr: errors.New("boom")}
		err := resetScopedDefault(zerolog.Nop(), fake.table(), added)
		assert.EqualError(t, err, "boom")
	})
	t.Run("permission denied hints at root", func(t *testing.T) {
		fake := &fakeRouteTable{
			routes:    []route.TableRoute{ownScopedDefault},
			deleteErr: unix.EPERM,
		}
		err := resetScopedDefault(zerolog.Nop(), fake.table(), added)
		require.ErrorIs(t, err, unix.EPERM)
		assert.Contains(t, err.Error(), "run spoofdpi as root")
	})
}
