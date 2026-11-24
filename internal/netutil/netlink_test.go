package netutil

import (
	"encoding/binary"
	"net/netip"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nlMessage encodes a netlink message the way the kernel sends it.
func nlMessage(typ, flags uint16, seq, pid uint32, payload []byte) []byte {
	b := appendNetlinkHeader(nil, len(payload), typ, flags, seq)
	binary.NativeEndian.PutUint32(b[12:16], pid)
	b = append(b, payload...)
	return append(b, make([]byte, nlAlign(len(b))-len(b))...)
}

func nlU32(v uint32) []byte { return binary.NativeEndian.AppendUint32(nil, v) }

func nlAddr(s string) []byte { return netip.MustParseAddr(s).AsSlice() }

// nlRoute encodes an rtmsg of family, dstLen, table and typ, followed by
// attrs.
func nlRoute(family, dstLen, table, typ uint8, attrs ...[]byte) []byte {
	b := []byte{family, dstLen, 0, 0, table, 0, 0, typ, 0, 0, 0, 0}
	for _, a := range attrs {
		b = append(b, a...)
	}
	return b
}

func nlAttr(typ uint16, val []byte) []byte { return appendAttr(nil, typ, val) }

// nlErrorPayload encodes the payload of an NLMSG_ERROR with errno.
func nlErrorPayload(errno int32) []byte {
	b := binary.NativeEndian.AppendUint32(nil, uint32(-errno))
	// The kernel echoes the request header after the code.
	return append(b, make([]byte, nlmsgHdrLen)...)
}

func TestEncodeRouteGet(t *testing.T) {
	t.Run("ipv4", func(t *testing.T) {
		b := encodeRouteGet(7, netip.MustParseAddr("192.0.2.1"))
		msgs, err := parseNetlinkMessages(b)
		require.NoError(t, err)
		require.Len(t, msgs, 1)
		m := msgs[0]
		assert.Equal(t, uint16(rtmGetRoute), m.typ)
		assert.Equal(t, uint16(nlmFRequest), m.flags, "a lookup, not a dump")
		assert.Equal(t, uint32(7), m.seq)
		assert.Equal(t, len(b), int(binary.NativeEndian.Uint32(b[0:4])))

		require.Len(t, m.data, rtmsgLen+8)
		assert.Equal(t, []byte{linuxAFInet, 32, 0, 0, 0, 0, 0, 0}, m.data[:8])
		assert.Equal(t, uint32(rtmFLookupTable), binary.NativeEndian.Uint32(m.data[8:12]))
		assert.Equal(t, nlAttr(rtaDst, nlAddr("192.0.2.1")), m.data[rtmsgLen:])
	})

	t.Run("ipv6", func(t *testing.T) {
		b := encodeRouteGet(8, netip.MustParseAddr("2001:db8::1"))
		msgs, err := parseNetlinkMessages(b)
		require.NoError(t, err)
		require.Len(t, msgs, 1)
		data := msgs[0].data
		assert.Equal(t, []byte{linuxAFInet6, 128}, data[:2])
		assert.Equal(t, nlAttr(rtaDst, nlAddr("2001:db8::1")), data[rtmsgLen:])
	})
}

func TestParseNetlinkMessages(t *testing.T) {
	b := append(
		nlMessage(rtmNewRoute, 0, 1, 42, []byte{1, 2, 3}),
		nlMessage(nlmsgDone, 2, 1, 42, nil)...,
	)
	msgs, err := parseNetlinkMessages(b)
	require.NoError(t, err)
	require.Len(t, msgs, 2)
	assert.Equal(t, netlinkMessage{
		typ: rtmNewRoute, seq: 1, pid: 42, data: []byte{1, 2, 3},
	}, msgs[0])
	assert.Equal(t, uint16(nlmsgDone), msgs[1].typ)
	assert.Equal(t, uint16(2), msgs[1].flags)

	t.Run("length beyond the buffer", func(t *testing.T) {
		bad := nlMessage(rtmNewRoute, 0, 1, 42, []byte{1, 2, 3, 4})
		_, err := parseNetlinkMessages(bad[:len(bad)-4])
		assert.Error(t, err)
	})
	t.Run("length below the header", func(t *testing.T) {
		bad := nlMessage(rtmNewRoute, 0, 1, 42, nil)
		binary.NativeEndian.PutUint32(bad[0:4], 8)
		_, err := parseNetlinkMessages(bad)
		assert.Error(t, err)
	})
}

func TestNetlinkMessageError(t *testing.T) {
	assert.NoError(t, netlinkMessageError(netlinkMessage{data: nlErrorPayload(0)}))

	err := netlinkMessageError(netlinkMessage{data: nlErrorPayload(linuxENETUNREACH)})
	var errno syscall.Errno
	require.ErrorAs(t, err, &errno)
	assert.Equal(t, syscall.Errno(linuxENETUNREACH), errno)

	assert.Error(t, netlinkMessageError(netlinkMessage{data: []byte{1}}))
}

func TestIsNoRouteErrno(t *testing.T) {
	errOf := func(errno int32) error {
		return netlinkMessageError(netlinkMessage{data: nlErrorPayload(errno)})
	}
	dst4 := netip.MustParseAddr("192.0.2.1")
	dst6 := netip.MustParseAddr("2001:db8::1")
	for _, dst := range []netip.Addr{dst4, dst6} {
		assert.True(t, isNoRouteErrno(errOf(linuxENETUNREACH), dst), dst)
		assert.True(t, isNoRouteErrno(errOf(linuxEHOSTUNREACH), dst), dst)
		assert.True(t, isNoRouteErrno(errOf(linuxEACCES), dst), dst)
		assert.False(t, isNoRouteErrno(errOf(1), dst), "EPERM %s", dst)
		assert.False(t, isNoRouteErrno(nil, dst), dst)
	}
	assert.True(t, isNoRouteErrno(errOf(linuxEINVAL), dst4), "EINVAL ipv4: blackhole")
	assert.False(t, isNoRouteErrno(errOf(linuxEINVAL), dst6), "EINVAL ipv6")
}

func TestCollectReply(t *testing.T) {
	route := netlinkMessage{typ: rtmNewRoute, seq: 5, pid: 42, data: []byte{1}}
	otherSeq := netlinkMessage{typ: rtmNewRoute, seq: 4, pid: 42}
	otherPid := netlinkMessage{typ: rtmNewRoute, seq: 5, pid: 43}
	done := netlinkMessage{typ: nlmsgDone, seq: 5, pid: 42, data: nlU32(0)}
	fail := netlinkMessage{typ: nlmsgError, seq: 5, pid: 42, data: nlErrorPayload(22)}
	ack := netlinkMessage{typ: nlmsgError, seq: 5, pid: 42, data: nlErrorPayload(0)}

	t.Run("lookup ends with its first message", func(t *testing.T) {
		got, ok, err := collectReply(
			nil,
			[]netlinkMessage{otherSeq, otherPid, route, route},
			5,
			42,
			false,
		)
		require.NoError(t, err)
		assert.True(t, ok)
		assert.Equal(t, []netlinkMessage{route}, got)
	})
	t.Run("lookup waits for its message", func(t *testing.T) {
		got, ok, err := collectReply(
			nil,
			[]netlinkMessage{otherSeq, otherPid},
			5,
			42,
			false,
		)
		require.NoError(t, err)
		assert.False(t, ok)
		assert.Empty(t, got)
	})
	t.Run("dump collects until done across receives", func(t *testing.T) {
		got, ok, err := collectReply(nil, []netlinkMessage{route, otherSeq}, 5, 42, true)
		require.NoError(t, err)
		assert.False(t, ok)
		got, ok, err = collectReply(got, []netlinkMessage{route, done, route}, 5, 42, true)
		require.NoError(t, err)
		assert.True(t, ok)
		assert.Equal(t, []netlinkMessage{route, route}, got)
	})
	t.Run("done with an errno fails the dump", func(t *testing.T) {
		failedDone := netlinkMessage{
			typ: nlmsgDone, seq: 5, pid: 42, data: nlErrorPayload(linuxEINVAL)[:4],
		}
		_, ok, err := collectReply(nil, []netlinkMessage{route, failedDone}, 5, 42, true)
		assert.True(t, ok)
		var errno syscall.Errno
		require.ErrorAs(t, err, &errno)
		assert.Equal(t, syscall.Errno(linuxEINVAL), errno)
	})
	t.Run("done without its errno is an error", func(t *testing.T) {
		shortDone := netlinkMessage{typ: nlmsgDone, seq: 5, pid: 42}
		_, ok, err := collectReply(nil, []netlinkMessage{shortDone}, 5, 42, true)
		assert.True(t, ok)
		assert.Error(t, err)
	})
	t.Run("interrupted dump", func(t *testing.T) {
		intr := route
		intr.flags = nlmFDumpIntr
		_, ok, err := collectReply(nil, []netlinkMessage{route, intr}, 5, 42, true)
		assert.True(t, ok)
		assert.ErrorIs(t, err, errNetlinkDumpInterrupted)

		intrDone := done
		intrDone.flags = nlmFDumpIntr
		_, _, err = collectReply(nil, []netlinkMessage{intrDone}, 5, 42, true)
		assert.ErrorIs(t, err, errNetlinkDumpInterrupted)
	})
	t.Run("error ends the reply", func(t *testing.T) {
		_, ok, err := collectReply(nil, []netlinkMessage{fail}, 5, 42, false)
		assert.True(t, ok)
		assert.Error(t, err)
	})
	t.Run("ack ends the reply without messages", func(t *testing.T) {
		got, ok, err := collectReply(nil, []netlinkMessage{ack}, 5, 42, false)
		require.NoError(t, err)
		assert.True(t, ok)
		assert.Empty(t, got)
	})
	t.Run("payloads are copies", func(t *testing.T) {
		buf := []byte{9}
		m := netlinkMessage{typ: rtmNewRoute, seq: 5, pid: 42, data: buf}
		got, _, err := collectReply(nil, []netlinkMessage{m}, 5, 42, false)
		require.NoError(t, err)
		buf[0] = 0
		assert.Equal(t, []byte{9}, got[0].data)
	})
}

func TestKernelRouteFromNetlink(t *testing.T) {
	reply := func(payload []byte) []netlinkMessage {
		return []netlinkMessage{{typ: rtmNewRoute, data: payload}}
	}

	tcs := []struct {
		name    string
		dst     string
		payload []byte
		want    kernelRoute
	}{
		{
			name: "ipv4 via gateway in main",
			dst:  "192.0.2.1",
			payload: nlRoute(linuxAFInet, 32, 254, rtnUnicast,
				nlAttr(rtaTable, nlU32(254)),
				nlAttr(rtaDst, nlAddr("192.0.2.1")),
				nlAttr(rtaOif, nlU32(2)),
				nlAttr(rtaPrefsrc, nlAddr("10.0.2.15")),
				nlAttr(rtaGateway, nlAddr("10.0.2.2")),
			),
			want: kernelRoute{
				ifIndex: 2,
				gateway: netip.MustParseAddr("10.0.2.2"),
				src:     netip.MustParseAddr("10.0.2.15"),
				table:   254,
			},
		},
		{
			name: "wg-quick table without gateway",
			dst:  "192.0.2.1",
			payload: nlRoute(linuxAFInet, 32, 252, rtnUnicast,
				nlAttr(rtaTable, nlU32(51820)),
				nlAttr(rtaOif, nlU32(7)),
				nlAttr(rtaPrefsrc, nlAddr("10.8.0.2")),
			),
			want: kernelRoute{
				ifIndex: 7,
				src:     netip.MustParseAddr("10.8.0.2"),
				table:   51820,
			},
		},
		{
			name:    "rtm_table without RTA_TABLE",
			dst:     "192.0.2.1",
			payload: nlRoute(linuxAFInet, 32, 100, rtnUnicast, nlAttr(rtaOif, nlU32(3))),
			want:    kernelRoute{ifIndex: 3, table: 100},
		},
		{
			name: "ipv6 link-local gateway",
			dst:  "2001:db8::1",
			payload: nlRoute(linuxAFInet6, 128, 254, rtnUnicast,
				nlAttr(rtaOif, nlU32(2)),
				nlAttr(rtaGateway, nlAddr("fe80::1")),
				nlAttr(rtaPrefsrc, nlAddr("2001:db8:1::2")),
			),
			want: kernelRoute{
				ifIndex: 2,
				gateway: netip.MustParseAddr("fe80::1"),
				src:     netip.MustParseAddr("2001:db8:1::2"),
				table:   254,
			},
		},
		{
			name: "nested and byte-order flags are masked",
			dst:  "192.0.2.1",
			payload: nlRoute(linuxAFInet, 32, 254, rtnUnicast,
				nlAttr(rtaOif|0x8000|0x4000, nlU32(2)),
				nlAttr(99, []byte{1, 2, 3}),
			),
			want: kernelRoute{ifIndex: 2, table: 254},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got, err := kernelRouteFromNetlink(reply(tc.payload), netip.MustParseAddr(tc.dst))
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestKernelRouteFromNetlink_Errors(t *testing.T) {
	dst4 := netip.MustParseAddr("192.0.2.1")
	oif := nlAttr(rtaOif, nlU32(2))
	reply := func(payload []byte) []netlinkMessage {
		return []netlinkMessage{{typ: rtmNewRoute, data: payload}}
	}

	for _, typ := range []uint8{rtnBlackhole, rtnUnreachable, rtnProhibit, rtnThrow} {
		_, err := kernelRouteFromNetlink(
			reply(nlRoute(linuxAFInet, 32, 254, typ, oif)),
			dst4,
		)
		assert.ErrorIs(t, err, ErrNoIPv4Route, "type %d", typ)
	}
	_, err := kernelRouteFromNetlink(
		reply(nlRoute(linuxAFInet6, 128, 254, rtnUnreachable, oif)),
		netip.MustParseAddr("2001:db8::1"),
	)
	assert.ErrorIs(t, err, ErrNoIPv6Route)

	tcs := []struct {
		name    string
		reply   []netlinkMessage
		wantMsg string
	}{
		{
			name:    "local route",
			reply:   reply(nlRoute(linuxAFInet, 32, 255, 2, oif)),
			wantMsg: "not unicast",
		},
		{
			name: "RTA_VIA",
			reply: reply(nlRoute(linuxAFInet, 32, 254, rtnUnicast, oif,
				nlAttr(rtaVia, append([]byte{linuxAFInet6, 0}, nlAddr("fe80::1")...)),
			)),
			wantMsg: "RTA_VIA",
		},
		{
			name:    "no output interface",
			reply:   reply(nlRoute(linuxAFInet, 32, 254, rtnUnicast)),
			wantMsg: "no output interface",
		},
		{
			name:    "other family",
			reply:   reply(nlRoute(linuxAFInet6, 128, 254, rtnUnicast, oif)),
			wantMsg: "address family",
		},
		{
			name:    "short route message",
			reply:   reply([]byte{linuxAFInet}),
			wantMsg: "short route message",
		},
		{
			name:    "bad attribute",
			reply:   reply(append(nlRoute(linuxAFInet, 32, 254, rtnUnicast), 0xff, 0, 4, 0)),
			wantMsg: "bad attribute",
		},
		{
			name:    "no message",
			wantMsg: "no route in the reply",
		},
		{
			name:    "not a route message",
			reply:   []netlinkMessage{{typ: nlmsgDone}},
			wantMsg: "no route in the reply",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			_, err := kernelRouteFromNetlink(tc.reply, dst4)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantMsg)
		})
	}
}

func TestEncodeRouteFIBMatch(t *testing.T) {
	t.Run("ipv4", func(t *testing.T) {
		b := encodeRouteFIBMatch(7, netip.MustParseAddr("10.0.0.1"))
		msgs, err := parseNetlinkMessages(b)
		require.NoError(t, err)
		require.Len(t, msgs, 1)
		m := msgs[0]
		assert.Equal(t, uint16(rtmGetRoute), m.typ)
		assert.Equal(t, uint16(nlmFRequest), m.flags, "a lookup, not a dump")
		assert.Equal(t, uint32(7), m.seq)
		assert.Equal(t, len(b), int(binary.NativeEndian.Uint32(b[0:4])))

		require.Len(t, m.data, rtmsgLen+8)
		assert.Equal(t, []byte{linuxAFInet, 32, 0, 0, 0, 0, 0, 0}, m.data[:8])
		assert.Equal(t, uint32(rtmFFibMatch), binary.NativeEndian.Uint32(m.data[8:12]))
		assert.Equal(t, nlAttr(rtaDst, nlAddr("10.0.0.1")), m.data[rtmsgLen:])
	})

	t.Run("ipv6", func(t *testing.T) {
		b := encodeRouteFIBMatch(8, netip.MustParseAddr("2001:db8::1"))
		msgs, err := parseNetlinkMessages(b)
		require.NoError(t, err)
		require.Len(t, msgs, 1)
		data := msgs[0].data
		assert.Equal(t, []byte{linuxAFInet6, 128}, data[:2])
		assert.Equal(t, uint32(rtmFFibMatch), binary.NativeEndian.Uint32(data[8:12]))
		assert.Equal(t, nlAttr(rtaDst, nlAddr("2001:db8::1")), data[rtmsgLen:])
	})
}

// TestPrefixFromNetlink decodes RTM_NEWROUTE replies laid out the way the
// kernel answers an RTM_F_FIB_MATCH lookup: the matched entry, with its
// own rtm_dst_len and RTA_DST, and no RTA_DST for a default route.
func TestPrefixFromNetlink(t *testing.T) {
	reply := func(payload []byte) []netlinkMessage {
		return []netlinkMessage{{typ: rtmNewRoute, data: payload}}
	}

	tcs := []struct {
		name    string
		dst     string
		payload []byte
		want    string
	}{
		{
			name: "default route",
			dst:  "10.0.0.1",
			payload: nlRoute(linuxAFInet, 0, 254, rtnUnicast,
				nlAttr(rtaTable, nlU32(254)),
				nlAttr(rtaGateway, nlAddr("10.0.2.2")),
				nlAttr(rtaOif, nlU32(2)),
			),
			want: "0.0.0.0/0",
		},
		{
			name: "vpn route to 10.0.0.0/8",
			dst:  "10.1.2.1",
			payload: nlRoute(linuxAFInet, 8, 254, rtnUnicast,
				nlAttr(rtaTable, nlU32(254)),
				nlAttr(rtaDst, nlAddr("10.0.0.0")),
				nlAttr(rtaOif, nlU32(7)),
			),
			want: "10.0.0.0/8",
		},
		{
			name: "full-tunnel /1 half",
			dst:  "192.0.2.1",
			payload: nlRoute(linuxAFInet, 1, 254, rtnUnicast,
				nlAttr(rtaDst, nlAddr("128.0.0.0")),
				nlAttr(rtaOif, nlU32(7)),
			),
			want: "128.0.0.0/1",
		},
		{
			name: "multipath route has no RTA_OIF",
			dst:  "172.16.0.1",
			payload: nlRoute(linuxAFInet, 12, 254, rtnUnicast,
				nlAttr(rtaDst, nlAddr("172.16.0.0")),
				nlAttr(rtaMultipath, []byte{8, 0, 0, 0, 2, 0, 0, 0}),
			),
			want: "172.16.0.0/12",
		},
		{
			name: "kernel without RTM_F_FIB_MATCH reports the full length",
			dst:  "192.0.2.1",
			payload: nlRoute(linuxAFInet, 32, 254, rtnUnicast,
				nlAttr(rtaDst, nlAddr("192.0.2.1")),
				nlAttr(rtaOif, nlU32(2)),
			),
			want: "192.0.2.1/32",
		},
		{
			name: "ipv6 route",
			dst:  "2001:db8::1",
			payload: nlRoute(linuxAFInet6, 32, 254, rtnUnicast,
				nlAttr(rtaDst, nlAddr("2001:db8::")),
				nlAttr(rtaOif, nlU32(2)),
			),
			want: "2001:db8::/32",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got, err := prefixFromNetlink(reply(tc.payload), netip.MustParseAddr(tc.dst))
			require.NoError(t, err)
			assert.Equal(t, netip.MustParsePrefix(tc.want), got)
		})
	}
}

func TestPrefixFromNetlink_Errors(t *testing.T) {
	dst4 := netip.MustParseAddr("10.0.0.1")
	reply := func(payload []byte) []netlinkMessage {
		return []netlinkMessage{{typ: rtmNewRoute, data: payload}}
	}

	// Types 2 and 3 are RTN_LOCAL and RTN_BROADCAST.
	for _, typ := range []uint8{2, 3, rtnBlackhole, rtnUnreachable, rtnProhibit, rtnThrow} {
		_, err := prefixFromNetlink(reply(nlRoute(linuxAFInet, 8, 254, typ)), dst4)
		assert.ErrorIs(t, err, ErrNoIPv4Route, "type %d", typ)
	}
	_, err := prefixFromNetlink(
		reply(nlRoute(linuxAFInet6, 64, 254, rtnUnreachable)),
		netip.MustParseAddr("2001:db8::1"),
	)
	assert.ErrorIs(t, err, ErrNoIPv6Route)

	tcs := []struct {
		name    string
		reply   []netlinkMessage
		wantMsg string
	}{
		{
			name:    "other family",
			reply:   reply(nlRoute(linuxAFInet6, 0, 254, rtnUnicast)),
			wantMsg: "address family",
		},
		{
			name:    "prefix length out of range",
			reply:   reply(nlRoute(linuxAFInet, 33, 254, rtnUnicast)),
			wantMsg: "prefix length 33 is out of range",
		},
		{
			name:    "short route message",
			reply:   reply([]byte{linuxAFInet}),
			wantMsg: "short route message",
		},
		{
			name:    "no message",
			wantMsg: "no route in the reply",
		},
		{
			name:    "not a route message",
			reply:   []netlinkMessage{{typ: nlmsgDone}},
			wantMsg: "no route in the reply",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			_, err := prefixFromNetlink(tc.reply, dst4)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantMsg)
		})
	}
}
