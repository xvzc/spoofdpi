package route

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/netutil"
)

// nlRouteFull encodes an rtmsg with every header field the dump parser
// reads, followed by attrs.
func nlRouteFull(
	family, dstLen, table, protocol, scope, typ uint8,
	attrs ...[]byte,
) []byte {
	b := []byte{family, dstLen, 0, 0, table, protocol, scope, typ, 0, 0, 0, 0}
	for _, a := range attrs {
		b = append(b, a...)
	}
	return b
}

func TestEncodeRouteModify(t *testing.T) {
	tcs := []struct {
		name      string
		route     RouteEntry
		add       bool
		wantTyp   uint16
		wantFlags uint16
		wantHdr   []byte
		wantAttrs []byte
	}{
		{
			name: "add ipv4 default dev in a 32-bit table",
			route: RouteEntry{
				Table:    0x53504401,
				Dst:      netip.MustParsePrefix("0.0.0.0/0"),
				Oif:      9,
				Protocol: 213,
				Scope:    RouteScopeLink,
			},
			add:       true,
			wantTyp:   rtmNewRoute,
			wantFlags: addFlags,
			wantHdr: []byte{
				linuxAFInet, 0, 0, 0, 0, 213, RouteScopeLink, rtnUnicast, 0, 0, 0, 0,
			},
			wantAttrs: append(
				nlAttr(rtaTable, nlU32(0x53504401)),
				nlAttr(rtaOif, nlU32(9))...,
			),
		},
		{
			name: "delete ipv6 prefix keeps a zero type",
			route: RouteEntry{
				Table:    0x53504401,
				Dst:      netip.MustParsePrefix("2000::/3"),
				Oif:      9,
				Protocol: 213,
			},
			wantTyp:   rtmDelRoute,
			wantFlags: delFlags,
			wantHdr:   []byte{linuxAFInet6, 3, 0, 0, 0, 213, 0, 0, 0, 0, 0, 0},
			wantAttrs: append(append(
				nlAttr(rtaTable, nlU32(0x53504401)),
				nlAttr(rtaDst, nlAddr("2000::"))...),
				nlAttr(rtaOif, nlU32(9))...,
			),
		},
		{
			name: "add ipv4 prefix via gateway in main",
			route: RouteEntry{
				Table:   254,
				Dst:     netip.MustParsePrefix("198.51.100.0/24"),
				Gateway: netip.MustParseAddr("192.0.2.1"),
				Type:    RouteTypeUnicast,
			},
			add:       true,
			wantTyp:   rtmNewRoute,
			wantFlags: addFlags,
			wantHdr:   []byte{linuxAFInet, 24, 0, 0, 0, 0, 0, rtnUnicast, 0, 0, 0, 0},
			wantAttrs: append(append(
				nlAttr(rtaTable, nlU32(254)),
				nlAttr(rtaDst, nlAddr("198.51.100.0"))...),
				nlAttr(rtaGateway, nlAddr("192.0.2.1"))...,
			),
		},
		{
			name: "delete ipv6 with a metric",
			route: RouteEntry{
				Table:    0x53504401,
				Dst:      netip.MustParsePrefix("2000::/3"),
				Metric:   1024,
				Protocol: 213,
			},
			wantTyp:   rtmDelRoute,
			wantFlags: delFlags,
			wantHdr:   []byte{linuxAFInet6, 3, 0, 0, 0, 213, 0, 0, 0, 0, 0, 0},
			wantAttrs: append(append(
				nlAttr(rtaTable, nlU32(0x53504401)),
				nlAttr(rtaDst, nlAddr("2000::"))...),
				nlAttr(rtaPriority, nlU32(1024))...,
			),
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			m := parseOneRequest(t, encodeRouteModify(11, tc.route, tc.add))
			assert.Equal(t, tc.wantTyp, m.typ)
			assert.Equal(t, tc.wantFlags, m.flags)
			assert.Equal(t, uint32(11), m.seq)
			require.GreaterOrEqual(t, len(m.data), rtmsgLen)
			assert.Equal(t, tc.wantHdr, m.data[:rtmsgLen])
			assert.Equal(t, tc.wantAttrs, m.data[rtmsgLen:])
		})
	}
}

func TestRouteEntriesFromNetlink(t *testing.T) {
	msg := func(payload []byte) netlinkMessage {
		return netlinkMessage{typ: rtmNewRoute, data: payload}
	}

	t.Run("ipv4", func(t *testing.T) {
		reply := []netlinkMessage{
			// default dev 9 table 0x53504401 proto 213 scope link
			msg(nlRouteFull(linuxAFInet, 0, 252, 213, RouteScopeLink, rtnUnicast,
				nlAttr(rtaTable, nlU32(0x53504401)),
				nlAttr(rtaOif, nlU32(9)),
			)),
			// 192.0.2.0/24 via 10.0.0.1 dev 2 proto static in main
			msg(nlRouteFull(linuxAFInet, 24, 254, 4, 0, rtnUnicast,
				nlAttr(rtaTable, nlU32(254)),
				nlAttr(rtaDst, nlAddr("192.0.2.0")),
				nlAttr(rtaGateway, nlAddr("10.0.0.1")),
				nlAttr(rtaOif, nlU32(2)),
			)),
			// A local route without RTA_TABLE keeps the header's table.
			msg(nlRouteFull(linuxAFInet, 32, 255, 2, 254, 2,
				nlAttr(rtaDst, nlAddr("127.0.0.1")),
				nlAttr(rtaOif, nlU32(1)),
			)),
			// Another family and other message types are skipped.
			msg(nlRouteFull(linuxAFInet6, 0, 254, 0, 0, rtnUnicast)),
			{typ: rtmNewLink, data: []byte{1}},
		}

		got, err := routeEntriesFromNetlink(reply, netutil.FamilyV4)
		require.NoError(t, err)
		assert.Equal(t, []RouteEntry{
			{
				Table:    0x53504401,
				Dst:      netip.MustParsePrefix("0.0.0.0/0"),
				Oif:      9,
				Protocol: 213,
				Scope:    RouteScopeLink,
				Type:     RouteTypeUnicast,
			},
			{
				Table:    254,
				Dst:      netip.MustParsePrefix("192.0.2.0/24"),
				Oif:      2,
				Gateway:  netip.MustParseAddr("10.0.0.1"),
				Protocol: 4,
				Type:     RouteTypeUnicast,
			},
			{
				Table:    255,
				Dst:      netip.MustParsePrefix("127.0.0.1/32"),
				Oif:      1,
				Protocol: 2,
				Scope:    254,
				Type:     2,
			},
		}, got)
	})

	t.Run("metric and other attributes", func(t *testing.T) {
		reply := []netlinkMessage{
			msg(nlRouteFull(linuxAFInet, 0, 254, 16, 0, rtnUnicast,
				nlAttr(rtaTable, nlU32(254)),
				nlAttr(rtaPriority, nlU32(600)),
				nlAttr(rtaPrefsrc, nlAddr("10.0.0.2")),
				nlAttr(rtaMultipath, make([]byte, 8)),
			)),
		}
		got, err := routeEntriesFromNetlink(reply, netutil.FamilyV4)
		require.NoError(t, err)
		assert.Equal(t, []RouteEntry{{
			Table:      254,
			Dst:        netip.MustParsePrefix("0.0.0.0/0"),
			Metric:     600,
			Protocol:   16,
			Type:       RouteTypeUnicast,
			OtherAttrs: []uint16{rtaPrefsrc, rtaMultipath},
		}}, got)
	})

	t.Run("tos", func(t *testing.T) {
		payload := nlRouteFull(linuxAFInet, 0, 254, 4, 0, rtnUnicast,
			nlAttr(rtaTable, nlU32(254)),
		)
		payload[3] = 0x10
		got, err := routeEntriesFromNetlink(
			[]netlinkMessage{msg(payload)},
			netutil.FamilyV4,
		)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, uint8(0x10), got[0].TOS)
	})

	t.Run("ipv6", func(t *testing.T) {
		reply := []netlinkMessage{
			msg(nlRouteFull(linuxAFInet6, 3, 252, 213, 0, rtnUnicast,
				nlAttr(rtaTable, nlU32(0x53504401)),
				nlAttr(rtaDst, nlAddr("2000::")),
				nlAttr(rtaOif, nlU32(9)),
			)),
			msg(nlRouteFull(linuxAFInet6, 0, 254, 9, 0, rtnUnicast,
				nlAttr(rtaTable, nlU32(254)),
				nlAttr(rtaGateway, nlAddr("fe80::1")),
				nlAttr(rtaOif, nlU32(2)),
			)),
		}

		got, err := routeEntriesFromNetlink(reply, netutil.FamilyV6)
		require.NoError(t, err)
		assert.Equal(t, []RouteEntry{
			{
				Table:    0x53504401,
				Dst:      netip.MustParsePrefix("2000::/3"),
				Oif:      9,
				Protocol: 213,
				Type:     RouteTypeUnicast,
			},
			{
				Table:    254,
				Dst:      netip.MustParsePrefix("::/0"),
				Oif:      2,
				Gateway:  netip.MustParseAddr("fe80::1"),
				Protocol: 9,
				Type:     RouteTypeUnicast,
			},
		}, got)
	})

	t.Run("prefix without its destination", func(t *testing.T) {
		reply := []netlinkMessage{msg(nlRouteFull(linuxAFInet, 24, 254, 0, 0, rtnUnicast))}
		_, err := routeEntriesFromNetlink(reply, netutil.FamilyV4)
		assert.Error(t, err)
	})

	t.Run("destination of another family", func(t *testing.T) {
		reply := []netlinkMessage{msg(nlRouteFull(linuxAFInet, 24, 254, 0, 0, rtnUnicast,
			nlAttr(rtaDst, nlAddr("2001:db8::")),
		))}
		_, err := routeEntriesFromNetlink(reply, netutil.FamilyV4)
		assert.Error(t, err)
	})

	t.Run("encoded add parses back", func(t *testing.T) {
		want := RouteEntry{
			Table:    0x53504401,
			Dst:      netip.MustParsePrefix("2000::/3"),
			Oif:      9,
			Metric:   1024,
			TOS:      0x10,
			Protocol: 213,
			Type:     RouteTypeUnicast,
		}
		m := parseOneRequest(t, encodeRouteModify(1, want, true))
		m.typ = rtmNewRoute
		got, err := routeEntriesFromNetlink([]netlinkMessage{m}, netutil.FamilyV6)
		require.NoError(t, err)
		assert.Equal(t, []RouteEntry{want}, got)
	})
}

func TestRouteEntryStringWithNames(t *testing.T) {
	e := RouteEntry{
		Table: 254,
		Dst:   netip.MustParsePrefix("192.0.2.0/24"),
		Oif:   2,
	}
	names := map[int]string{2: "eth0"}
	lookup := func(i int) string { return names[i] }

	assert.Equal(t, "192.0.2.0/24 dev eth0 table 254 proto 0 scope 0 type 0",
		e.StringWithNames(lookup))
	e.Oif = 3
	assert.Equal(t, "192.0.2.0/24 dev 3 table 254 proto 0 scope 0 type 0",
		e.StringWithNames(lookup), "an unknown index stays an index")
	assert.Equal(t, e.String(), e.StringWithNames(nil))
}

func TestRouteEntryString(t *testing.T) {
	assert.Equal(
		t,
		"default dev 9 table 1397769217 proto 213 scope 253 type 0",
		RouteEntry{
			Table:    0x53504401,
			Dst:      netip.MustParsePrefix("0.0.0.0/0"),
			Oif:      9,
			Protocol: 213,
			Scope:    RouteScopeLink,
		}.String(),
	)
	assert.Equal(
		t,
		"2000::/3 via fe80::1 dev 2 table 254 proto 0 scope 0 type 1",
		RouteEntry{
			Table:   254,
			Dst:     netip.MustParsePrefix("2000::/3"),
			Oif:     2,
			Gateway: netip.MustParseAddr("fe80::1"),
			Type:    RouteTypeUnicast,
		}.String(),
	)
}

func TestCheckRoute(t *testing.T) {
	valid := RouteEntry{
		Table:    0x53504401,
		Dst:      netip.MustParsePrefix("0.0.0.0/0"),
		Oif:      9,
		Protocol: 213,
	}
	with := func(edit func(r *RouteEntry)) RouteEntry {
		r := valid
		edit(&r)
		return r
	}

	tcs := []struct {
		name      string
		route     RouteEntry
		addErr    bool
		deleteErr bool
	}{
		{name: "valid", route: valid},
		{
			name:      "no destination",
			route:     with(func(r *RouteEntry) { r.Dst = netip.Prefix{} }),
			addErr:    true,
			deleteErr: true,
		},
		{
			name: "host bits set",
			route: with(func(r *RouteEntry) {
				r.Dst = netip.MustParsePrefix("192.0.2.1/24")
			}),
			addErr:    true,
			deleteErr: true,
		},
		{
			name: "gateway of another family",
			route: with(func(r *RouteEntry) {
				r.Gateway = netip.MustParseAddr("fe80::1")
			}),
			addErr:    true,
			deleteErr: true,
		},
		{
			name:      "delete without a table",
			route:     with(func(r *RouteEntry) { r.Table = 0 }),
			deleteErr: true,
		},
		{
			name:      "delete without a protocol tag",
			route:     with(func(r *RouteEntry) { r.Protocol = 0 }),
			deleteErr: true,
		},
		{
			name:      "delete with a TOS",
			route:     with(func(r *RouteEntry) { r.TOS = 0x10 }),
			deleteErr: true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.addErr, checkRoute(tc.route) != nil, "add")
			assert.Equal(t, tc.deleteErr, checkRouteDelete(tc.route) != nil, "delete")
		})
	}
}

func TestRouteDeleteAmbiguous(t *testing.T) {
	target := RouteEntry{
		Table:    0x53504401,
		Dst:      netip.MustParsePrefix("0.0.0.0/0"),
		Oif:      9,
		Protocol: 213,
		Scope:    RouteScopeLink,
		Type:     RouteTypeUnicast,
	}
	target6 := RouteEntry{
		Table:      0x53504401,
		Dst:        netip.MustParsePrefix("2000::/3"),
		Oif:        9,
		Metric:     1024,
		Protocol:   213,
		Type:       RouteTypeUnicast,
		OtherAttrs: []uint16{12, 20},
	}
	with := func(r RouteEntry, edit func(r *RouteEntry)) RouteEntry {
		edit(&r)
		return r
	}

	tcs := []struct {
		name   string
		target RouteEntry
		dump   []RouteEntry
		want   bool
	}{
		{name: "empty dump", target: target},
		{name: "only the target", target: target, dump: []RouteEntry{target}},
		{
			name:   "routes of other tables, prefixes, tags and links",
			target: target,
			dump: []RouteEntry{
				with(target, func(r *RouteEntry) { r.Table = 254 }),
				with(target, func(r *RouteEntry) {
					r.Dst = netip.MustParsePrefix("0.0.0.0/1")
				}),
				with(target, func(r *RouteEntry) { r.Protocol = 4 }),
				with(target, func(r *RouteEntry) { r.Oif = 2 }),
				with(target, func(r *RouteEntry) { r.Scope = RouteScopeUniverse }),
				target,
			},
		},
		{
			name:   "a route with a gateway on the same link",
			target: target,
			dump: []RouteEntry{target, with(target, func(r *RouteEntry) {
				r.Gateway = netip.MustParseAddr("192.0.2.1")
			})},
			want: true,
		},
		{
			name:   "the TOS is not compared",
			target: target,
			dump:   []RouteEntry{target, with(target, func(r *RouteEntry) { r.TOS = 0x10 })},
			want:   true,
		},
		{
			name:   "another metric",
			target: target,
			dump:   []RouteEntry{target, with(target, func(r *RouteEntry) { r.Metric = 5 })},
			want:   true,
		},
		{
			name:   "a multipath route hides its links",
			target: target,
			dump: []RouteEntry{target, with(target, func(r *RouteEntry) {
				r.Oif = 0
				r.OtherAttrs = []uint16{rtaMultipath}
			})},
			want: true,
		},
		{
			name:   "target missing but another route matches",
			target: target,
			dump: []RouteEntry{with(target, func(r *RouteEntry) {
				r.OtherAttrs = []uint16{rtaPrefsrc}
			})},
			want: true,
		},
		{
			name:   "ipv6 ignores the scope",
			target: target6,
			dump: []RouteEntry{target6, with(target6, func(r *RouteEntry) {
				r.Scope = RouteScopeLink
			})},
			want: true,
		},
		{
			name:   "ipv6 compares the metric",
			target: target6,
			dump: []RouteEntry{
				target6,
				with(target6, func(r *RouteEntry) { r.Metric = 1 }),
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, RouteDeleteAmbiguous(tc.target, tc.dump))
		})
	}
}
