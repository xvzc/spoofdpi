package netutil

import (
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

// TestNetlinkConstants_MatchOS checks the constants that netlink.go keeps
// for every OS against the Linux definitions.
func TestNetlinkConstants_MatchOS(t *testing.T) {
	assert.Equal(t, unix.SizeofNlMsghdr, nlmsgHdrLen)
	assert.Equal(t, unix.NLMSG_ERROR, nlmsgError)
	assert.Equal(t, unix.NLMSG_DONE, nlmsgDone)
	assert.Equal(t, unix.NLM_F_REQUEST, nlmFRequest)
	assert.Equal(t, unix.NLM_F_DUMP, nlmFDump)
	assert.Equal(t, unix.NLM_F_DUMP_INTR, nlmFDumpIntr)
	assert.Equal(t, ^(unix.NLA_F_NESTED|unix.NLA_F_NET_BYTEORDER)&0xffff, nlaTypeMask)

	assert.Equal(t, unix.RTM_NEWROUTE, rtmNewRoute)
	assert.Equal(t, unix.RTM_GETROUTE, rtmGetRoute)
	assert.Equal(t, unix.SizeofRtMsg, rtmsgLen)
	assert.Equal(t, unix.RTM_F_LOOKUP_TABLE, rtmFLookupTable)

	assert.Equal(t, unix.RTA_DST, rtaDst)
	assert.Equal(t, unix.RTA_OIF, rtaOif)
	assert.Equal(t, unix.RTA_GATEWAY, rtaGateway)
	assert.Equal(t, unix.RTA_PREFSRC, rtaPrefsrc)
	assert.Equal(t, unix.RTA_TABLE, rtaTable)
	assert.Equal(t, unix.RTA_VIA, rtaVia)

	assert.Equal(t, unix.RTN_UNICAST, rtnUnicast)
	assert.Equal(t, unix.RTN_BLACKHOLE, rtnBlackhole)
	assert.Equal(t, unix.RTN_UNREACHABLE, rtnUnreachable)
	assert.Equal(t, unix.RTN_PROHIBIT, rtnProhibit)
	assert.Equal(t, unix.RTN_THROW, rtnThrow)

	assert.Equal(t, unix.AF_INET, linuxAFInet)
	assert.Equal(t, unix.AF_INET6, linuxAFInet6)

	assert.Equal(t, syscall.EACCES, syscall.Errno(linuxEACCES))
	assert.Equal(t, syscall.EINVAL, syscall.Errno(linuxEINVAL))
	assert.Equal(t, syscall.ENETUNREACH, syscall.Errno(linuxENETUNREACH))
	assert.Equal(t, syscall.EHOSTUNREACH, syscall.Errno(linuxEHOSTUNREACH))
}
