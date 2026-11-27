package route

import (
	"fmt"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"golang.org/x/sys/unix"
)

// TestNetlinkModifyConstants_MatchOS checks the constants of the requests
// that change addresses, links, routes and rules against the Linux
// definitions. x/sys/unix has neither fib_rule_hdr, whose 12 bytes are
// family, dst_len, src_len, tos, table, res1, res2, action and a u32 of
// flags, nor RTA_NH_ID, which is 30.
func TestNetlinkModifyConstants_MatchOS(t *testing.T) {
	assert.Equal(t, unix.NLM_F_ACK, nlmFAck)
	assert.Equal(t, unix.NLM_F_EXCL, nlmFExcl)
	assert.Equal(t, unix.NLM_F_CREATE, nlmFCreate)

	assert.Equal(t, unix.RTM_NEWADDR, rtmNewAddr)
	assert.Equal(t, unix.RTM_DELADDR, rtmDelAddr)
	assert.Equal(t, unix.RTM_DELROUTE, rtmDelRoute)
	assert.Equal(t, unix.SizeofIfAddrmsg, ifaddrmsgLen)
	assert.Equal(t, unix.IFA_ADDRESS, ifaAddress)
	assert.Equal(t, unix.IFA_LOCAL, ifaLocal)
	assert.Equal(t, unix.IFF_UP, iffUp)

	assert.Equal(t, unix.RTA_PRIORITY, rtaPriority)
	assert.Equal(t, unix.RT_SCOPE_NOWHERE, rtScopeNowhere)
	assert.Equal(t, unix.RT_SCOPE_UNIVERSE, int(RouteScopeUniverse))
	assert.Equal(t, unix.RT_SCOPE_LINK, int(RouteScopeLink))

	assert.Equal(t, unix.RTM_NEWRULE, rtmNewRule)
	assert.Equal(t, unix.RTM_DELRULE, rtmDelRule)
	assert.Equal(t, unix.RTM_GETRULE, rtmGetRule)
	assert.Equal(t, unix.FRA_SRC, fraSrc)
	assert.Equal(t, unix.FRA_PRIORITY, fraPriority)
	assert.Equal(t, unix.FRA_FWMARK, fraFwmark)
	assert.Equal(t, unix.FRA_SUPPRESS_PREFIXLEN, fraSuppressPrefixlen)
	assert.Equal(t, unix.FRA_TABLE, fraTable)
	assert.Equal(t, unix.FRA_FWMASK, fraFwmask)
	assert.Equal(t, unix.FRA_PROTOCOL, fraProtocol)
	assert.Equal(t, unix.FR_ACT_TO_TBL, frActToTbl)
	assert.Equal(t, unix.FIB_RULE_INVERT, fibRuleInvert)
}

// TestRulesAndRoutes_Live dumps the real rules and routes, which needs no
// privileges.
func TestRulesAndRoutes_Live(t *testing.T) {
	for _, fam := range []netutil.Family{netutil.FamilyV4, netutil.FamilyV6} {
		rules, err := Rules(fam)
		require.NoError(t, err, fam)
		for _, r := range rules {
			t.Logf("rule: %s", r)
		}
		routes, err := Routes(fam)
		require.NoError(t, err, fam)
		t.Logf("%s: %d routes", fam, len(routes))
	}

	supported, err := RuleProtocolSupported()
	require.NoError(t, err)
	t.Logf("FRA_PROTOCOL supported: %v", supported)
}

// TestIsNotExist checks the errnos of missing objects against the kernel's
// answer as netlinkMessageError wraps it.
func TestIsNotExist(t *testing.T) {
	kernelErr := func(errno syscall.Errno) error {
		msg := netlinkMessage{data: nlErrorPayload(int32(errno))}
		return fmt.Errorf("delete: %w", netlinkMessageError(msg))
	}
	for _, errno := range []syscall.Errno{
		syscall.EADDRNOTAVAIL, syscall.ENODEV, syscall.ENOENT, syscall.ESRCH,
	} {
		assert.True(t, IsNotExist(kernelErr(errno)), errno)
	}
	assert.False(t, IsNotExist(kernelErr(syscall.EEXIST)))
	assert.False(t, IsNotExist(kernelErr(syscall.EPERM)))
	assert.False(t, IsNotExist(nil))
}
