//go:build network && linux

package tun

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/route"
	"github.com/xvzc/spoofdpi/internal/server"
	"github.com/xvzc/spoofdpi/internal/testutil"
)

// TestEgressControlLive_Mark_RequireRoot opens a socket with EgressControl
// pinned to lo and checks that its SO_MARK, read back, is egressFwmark, the
// mark that lets TUN mode's own sockets pass its capture rule.
func TestEgressControlLive_Mark_RequireRoot(t *testing.T) {
	testutil.RequireRoot(t)
	lo, err := net.InterfaceByName("lo")
	require.NoError(t, err)
	control := EgressControl(&route.Route{Iface: *lo}, 0)
	require.NotNil(t, control)

	lc := net.ListenConfig{Control: control}
	conn, err := lc.ListenPacket(context.Background(), "udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	sc, ok := conn.(syscall.Conn)
	require.True(t, ok)
	raw, err := sc.SyscallConn()
	require.NoError(t, err)
	var mark int
	var sockErr error
	require.NoError(t, raw.Control(func(fd uintptr) {
		mark, sockErr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK)
	}))
	require.NoError(t, sockErr)
	assert.Equal(t, egressFwmark, mark, "SO_MARK of the socket")
}

// TestCaptureJobsLive_RequireRoot applies TUN mode's jobs to a real TUN in
// a network namespace of its own, so the host's rules and routes are left
// alone. It checks that the leftover search leaves a live run alone, that
// the reset leaves nothing behind, and that the leftover search removes
// everything a run leaves when it ends without a reset, as on kill -9.
//
// The namespace belongs to the test's thread, so the test has no subtests,
// which would run on other threads.
func TestCaptureJobsLive_RequireRoot(t *testing.T) {
	testutil.RequireRoot(t)
	// Never unlocked: the thread ends with the test, and the namespace
	// with it. Every netlink call must run on this goroutine: helpers that
	// run their condition on another goroutine, such as testify's
	// Eventually, EventuallyWithT and Never, would see the host's
	// namespace.
	runtime.LockOSThread()
	if err := syscall.Unshare(syscall.CLONE_NEWNET); err != nil {
		t.Skipf("unshare CLONE_NEWNET: %v", err)
	}
	if ok, err := route.RuleProtocolSupported(); err != nil || !ok {
		t.Skipf("the kernel does not keep rule tags: %v", err)
	}
	logger := zerolog.New(zerolog.NewTestWriter(t))
	nl := systemNetlink{}
	before := liveSnapshot(t, nl)

	dev, err := createTunDevice()
	require.NoError(t, err)
	t.Cleanup(func() { _ = dev.Close() })
	tunIndex, err := nl.TUNIndex()
	require.NoError(t, err)
	require.NotZero(t, tunIndex)

	info := liveNetworkInfo(t, before, tunIndex)
	run := captureRun{
		table: info.CaptureTableID,
		prefs: map[netutil.Family][]uint32{
			netutil.FamilyV4: {info.MainRulePref, info.FromRulePref, info.CaptureRulePref},
		},
	}
	if info.IPv6MainRulePref != 0 {
		run.prefs[netutil.FamilyV6] = []uint32{
			info.IPv6MainRulePref,
			info.IPv6CaptureRulePref,
		}
	}
	jobs := buildJobs(info)

	applied, err := server.ApplyJobs(logger, jobs)
	require.NoError(t, err)
	applySnap := liveSnapshot(t, nl)
	var appliedRules []route.Rule
	for _, j := range applied {
		if a, ok := j.Apply.(ruleAction); ok {
			appliedRules = append(appliedRules, dumpedRuleOf(a.rule))
		}
	}
	assert.ElementsMatch(t, appliedRules, taggedRules(applySnap),
		"the dump shows the rules applied, tagged")
	assert.NotEmpty(t, scanCapture(applySnap).anchors)

	cleanCaptureLeftovers(logger, nl)
	assert.Equal(t, applySnap, liveSnapshot(t, nl), "a live run is left alone")

	server.ResetJobs(logger, applied)
	resetSnap := liveSnapshot(t, nl)
	assert.Empty(t, leftoversAfterReset(resetSnap, run), "the reset leaves nothing")
	assert.Equal(t, before.rules, resetSnap.rules)

	_, err = server.ApplyJobs(logger, jobs)
	require.NoError(t, err)
	require.NoError(t, dev.Close(), "close the TUN as the kernel does on kill -9")
	require.True(
		t,
		waitTUNGone(nl, 5*time.Second),
		"the TUN goes away with its last file",
	)

	crashSnap := liveSnapshot(t, nl)
	assert.NotEmpty(t, scanCapture(crashSnap).anchors, "the crashed run left its anchor")
	cleanCaptureLeftovers(logger, nl)
	assert.Equal(t, before.rules, liveSnapshot(t, nl).rules,
		"the leftover search removes every rule of the crashed run")
	assert.Equal(t, before.routes, liveSnapshot(t, nl).routes)
}

// waitTUNGone polls, on the calling goroutine, until linuxTUNName is gone
// or timeout passes, and reports whether it is gone.
func waitTUNGone(nl systemNetlink, timeout time.Duration) bool {
	for deadline := time.Now().Add(timeout); ; {
		if index, err := nl.TUNIndex(); err == nil && index == 0 {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// liveSnapshot dumps the rules and routes of the test's namespace.
func liveSnapshot(t *testing.T, nl systemNetlink) captureSnapshot {
	t.Helper()
	snap, err := takeCaptureSnapshot(nl)
	require.NoError(t, err)
	return snap
}

// dumpedRuleOf returns r as the kernel dumps it: without a mark of 0.
func dumpedRuleOf(r route.Rule) route.Rule {
	if r.HasFwmark && r.Fwmark == 0 {
		r.HasFwmark = false
	}
	return r
}

// taggedRules returns the rules of snap that carry TUN mode's tag.
func taggedRules(snap captureSnapshot) []route.Rule {
	var tagged []route.Rule
	for _, fam := range captureFamilies {
		for _, r := range snap.rules[fam] {
			if isTagged(r) {
				tagged = append(tagged, r)
			}
		}
	}
	return tagged
}

// liveNetworkInfo returns the network info of a run on the TUN with
// tunIndex, with the table and prefs chosen from snap as collectNetworkInfo
// chooses them.
func liveNetworkInfo(
	t *testing.T,
	snap captureSnapshot,
	tunIndex int,
) *tunNetworkInfoLinux {
	t.Helper()
	var rules []route.Rule
	var routes []route.RouteEntry
	for _, fam := range captureFamilies {
		rules = append(rules, snap.rules[fam]...)
		routes = append(routes, snap.routes[fam]...)
	}
	table, err := freeCaptureTable(rules, routes)
	require.NoError(t, err)
	ipv4Prefs, _, err := freeRulePrefs(snap.rules[netutil.FamilyV4], 3)
	require.NoError(t, err)
	ipv6Prefs, _, err := freeRulePrefs(snap.rules[netutil.FamilyV6], 2)
	if err != nil {
		ipv6Prefs = nil
	}
	prefs := assignRulePrefs(ipv4Prefs, ipv6Prefs)
	return &tunNetworkInfoLinux{
		CaptureTableID:      table,
		TUNName:             linuxTUNName,
		TUNIndex:            tunIndex,
		PhysIfaceIP:         netip.MustParseAddr("192.0.2.1"),
		TunLocalIP:          netip.MustParseAddr("198.18.0.1"),
		TunRemoteIP:         netip.MustParseAddr("198.18.0.2"),
		MainRulePref:        prefs.main,
		FromRulePref:        prefs.from,
		CaptureRulePref:     prefs.capture,
		IPv6MainRulePref:    prefs.ipv6Main,
		IPv6CaptureRulePref: prefs.ipv6Capture,
		IPv6Enabled:         true,
		HasIPv6Egress:       true,
		TunIPv6Disabled: ipv6Disabled(
			fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/disable_ipv6", linuxTUNName),
		),
	}
}
