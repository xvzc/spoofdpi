//go:build network && darwin

package tun

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/netif"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/packetio/capture"
	"github.com/xvzc/spoofdpi/internal/packetio/inject"
	"github.com/xvzc/spoofdpi/internal/route"
	"github.com/xvzc/spoofdpi/internal/server"
	"github.com/xvzc/spoofdpi/internal/testutil"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
)

// testNet1 is a TEST-NET-1 address (RFC 5737) that no host answers.
var testNet1 = netip.MustParseAddr("192.0.2.1")

// TestEgressControlLive_RawSocket_RequireRoot pins the raw IPv4 socket of fake packets
// with EgressControl, as TUN mode does, and checks that the pin holds:
//   - the socket's IP_BOUND_IF, read back, is the pinned interface;
//   - pinned to the interface of the default route, a TTL 1 packet to
//     TEST-NET-1 leaves on that interface.
//
// Run it while spoofdpi's TUN mode is up to check that pinned fakes escape
// the TUN's 0/1 and 128/1 routes.
//
// It does not pin to lo0 to see a send fail: darwin ignores IP_BOUND_IF
// set to the loopback interface, and the packet leaves by the default
// route.
func TestEgressControlLive_RawSocket_RequireRoot(t *testing.T) {
	testutil.RequireRoot(t)
	rt := internetRoute(t)
	src, ok := netip.AddrFromSlice(rt.LocalIP)
	require.True(t, ok)
	src = src.Unmap()

	t.Run("default interface", func(t *testing.T) {
		h, err := capture.NewHandleWithReadTimeout(&rt.Iface, 100*time.Millisecond)
		require.NoError(t, err)
		t.Cleanup(h.Close)
		dh, ok := h.(*capture.DefaultHandle)
		require.True(t, ok)
		require.NoError(t, dh.SetBPFFilter(fmt.Sprintf(
			"tcp and src port 47002 and dst host %s and dst port 9", testNet1,
		)))

		s := openPinned(t, rt)
		require.NoError(t, s.Send(tcpPacket(t, src, testNet1, 47002)))

		seen := false
		for deadline := time.Now().Add(3 * time.Second); !seen && time.Now().Before(deadline); {
			data, _, err := h.ReadPacketData()
			if capture.IsReadTimeout(err) {
				continue
			}
			require.NoError(t, err)
			pkt := gopacket.NewPacket(data, h.LinkType(), gopacket.Default)
			ip4, ok := pkt.NetworkLayer().(*layers.IPv4)
			seen = ok && ip4.TTL == 1
		}
		assert.True(t, seen, "the pinned fake leaves on %s", rt.Iface.Name)
	})
}

// openPinned opens the IPv4 sender of fake packets pinned to rt's
// interface, and checks that the raw socket's IP_BOUND_IF is that
// interface.
func openPinned(t *testing.T, rt *route.Route) inject.Sender {
	t.Helper()
	control := EgressControl(rt, 0)
	require.NotNil(t, control)

	boundIndex := -1
	readBack := func(network, address string, c syscall.RawConn) error {
		if err := control(network, address, c); err != nil {
			return err
		}
		var sockErr error
		err := c.Control(func(fd uintptr) {
			boundIndex, sockErr = syscall.GetsockoptInt(
				int(fd), syscall.IPPROTO_IP, syscall.IP_BOUND_IF,
			)
		})
		if err != nil {
			return err
		}
		return sockErr
	}

	s, err := inject.Open(netutil.FamilyV4, inject.Options{Control: readBack})
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	assert.Equal(t, rt.Iface.Index, boundIndex, "IP_BOUND_IF of the raw socket")
	return s
}

// tcpPacket returns a TTL 1 ACK segment from src:srcPort to dst:9.
func tcpPacket(t *testing.T, src, dst netip.Addr, srcPort uint16) inject.Packet {
	t.Helper()
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: 9,
		Seq:     0x5eed0001,
		Ack:     0x5eed0002,
		ACK:     true,
		Window:  12345,
	}
	require.NoError(t, tcp.SetNetworkLayerForChecksum(&layers.IPv4{
		SrcIP:    src.AsSlice(),
		DstIP:    dst.AsSlice(),
		Protocol: layers.IPProtocolTCP,
	}))
	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, tcp))
	return inject.Packet{Src: src, Dst: dst, Proto: 6, HopLimit: 1, L4: buf.Bytes()}
}

// testNetworkInfo returns the network info of TUN mode on a new utun, with
// two changes that keep the host's traffic where it is: the TUN takes
// TEST-NET-2 and TEST-NET-3 (RFC 5737) in place of the 0/1 and 128/1
// halves, and the physical interface is lo0 with the gateway 127.0.0.1,
// so the scoped default route serves only sockets bound to lo0. The utun
// is closed when the test ends.
func testNetworkInfo(t *testing.T) (*tunNetworkInfoDarwin, tun.Device) {
	t.Helper()
	dev, err := createTunDevice()
	require.NoError(t, err)
	var closeOnce sync.Once
	t.Cleanup(func() { closeOnce.Do(func() { _ = dev.Close() }) })
	tunName, err := dev.Name()
	require.NoError(t, err)
	tunIface, err := net.InterfaceByName(tunName)
	require.NoError(t, err)
	lo, err := net.InterfaceByName("lo0")
	require.NoError(t, err)

	cidr, err := route.FindSafeCIDR()
	require.NoError(t, err)
	tunCIDR := netip.MustParsePrefix(cidr).Masked()

	routes, err := route.DumpRoutes(netutil.FamilyV4, 0)
	require.NoError(t, err)
	require.Nil(t, systemScopedDefault(routes, lo.Index),
		"lo0 has a scoped default route before the test")

	return &tunNetworkInfoDarwin{
		Gateway:        netip.MustParseAddr("127.0.0.1"),
		PhysIfaceName:  lo.Name,
		PhysIfaceIndex: lo.Index,
		TUNName:        tunName,
		TUNIndex:       tunIface.Index,
		TunLocal:       netip.PrefixFrom(tunCIDR.Addr().Next(), tunCIDR.Bits()),
		TunRemote:      tunCIDR.Addr().Next().Next(),
		RouteTargetCIDRs: []netip.Prefix{
			tunCIDR,
			netip.MustParsePrefix("198.51.100.0/24"),
			netip.MustParsePrefix("203.0.113.0/24"),
		},
	}, &closingDevice{Device: dev, once: &closeOnce}
}

// closingDevice closes its utun once, however often Close is called.
type closingDevice struct {
	tun.Device
	once *sync.Once
}

func (d *closingDevice) Close() error {
	d.once.Do(func() { _ = d.Device.Close() })
	return nil
}

// dumpedRoute returns the route of the dump that a, a route of the jobs,
// added, and whether there is one.
func dumpedRoute(t *testing.T, a route.TableRoute) (route.TableRoute, bool) {
	t.Helper()
	routes, err := route.DumpRoutes(netutil.FamilyV4, 0)
	require.NoError(t, err)
	for _, r := range routes {
		if isAddedRoute(r, a) {
			return r, true
		}
	}
	return route.TableRoute{}, false
}

// applyTestJobs applies the jobs of info and resets them when the test
// ends, unless the test reset them.
func applyTestJobs(t *testing.T, info *tunNetworkInfoDarwin) []route.TableRoute {
	t.Helper()
	jobs := buildJobs(zerolog.Nop(), info)
	applied, err := server.ApplyJobs(zerolog.New(io.Discard), jobs)
	require.NoError(t, err)
	require.Len(t, applied, len(jobs))
	added := addedRoutes(jobs)
	require.Len(t, added, len(info.RouteTargetCIDRs)+1)
	t.Cleanup(func() {
		for _, a := range slices.Backward(added) {
			if _, there := dumpedRoute(t, a); there {
				assert.NoError(t, deleteRouteAction{route: a}.Run(), "clean up %s", a)
			}
		}
	})
	return added
}

// testRouteTable returns the host's routing table as the leftover search
// of a test sees it: the routes on the interface with index, which the
// test configures, and the routes through utuns, which show running
// instances. A leftover of the host elsewhere stays out of the test's
// reach.
func testRouteTable(t *testing.T, index int) routeTable {
	t.Helper()
	table := systemRouteTable
	table.dump = func(fam netutil.Family) ([]route.TableRoute, error) {
		routes, err := systemRouteTable.dump(fam)
		if err != nil {
			return nil, err
		}
		names, err := systemRouteTable.interfaceNames()
		if err != nil {
			return nil, err
		}
		return slices.DeleteFunc(routes, func(r route.TableRoute) bool {
			onIndex := r.Index == index || r.GatewayLink == index
			throughUTUN := isUTUN(names[r.Index]) || isUTUN(names[r.GatewayLink]) ||
				isUTUN(r.IfName)
			return !onIndex && !throughUTUN
		}), nil
	}
	return table
}

// TestJobs_RequireRoot applies the TUN mode jobs on a new utun, checks
// that their routes are tagged and that the leftover search takes them
// for a running instance, then resets them and checks that none is left.
func TestJobs_RequireRoot(t *testing.T) {
	testutil.RequireRoot(t)
	info, _ := testNetworkInfo(t)
	table := testRouteTable(t, info.PhysIfaceIndex)
	var resetLogs bytes.Buffer
	jobs := buildJobs(zerolog.New(&resetLogs), info)
	applied, err := server.ApplyJobs(zerolog.New(io.Discard), jobs)
	require.NoError(t, err)
	reset := sync.OnceFunc(func() { server.ResetJobs(zerolog.New(io.Discard), applied) })
	t.Cleanup(reset)

	flags, err := netif.Flags(info.TUNName)
	require.NoError(t, err)
	assert.NotZero(t, flags&unix.IFF_UP, "%s is up", info.TUNName)
	for _, a := range addedRoutes(jobs) {
		r, ok := dumpedRoute(t, a)
		if assert.True(t, ok, "%s is in the table", a) {
			t.Logf("dumped: %s", r)
			assert.NotZero(t, r.Flags&unix.RTF_STATIC, "%s is static", r)
		}
		if isScopedDefault4(a) {
			assert.True(t, isOwnScopedDefaultShape(r),
				"%s has the shape of a TUN mode leftover", r)
		} else {
			assert.True(t, isLiveTUNRoute(r, map[int]string{info.TUNIndex: info.TUNName}),
				"%s shows a running instance", r)
		}
	}

	var logs bytes.Buffer
	cleanLeftovers(zerolog.New(&logs), table)
	assert.Contains(t, logs.String(), "another spoofdpi instance is running")
	_, ok := dumpedRoute(t, scopedDefaultRoute(info))
	assert.True(t, ok, "the scoped default route of a running instance stays")

	reset()
	assert.Empty(t, resetLogs.String(), "the reset deletes the scoped default route")
	logs.Reset()
	checkLeftoversAfterReset(zerolog.New(&logs), table, addedRoutes(jobs))
	assert.Empty(t, logs.String(), "no route is left after the reset")
}

// TestCleanLeftovers_AfterCrash_RequireRoot applies the TUN mode jobs,
// closes the utun as the end of a crashed process does, and checks that
// the leftover search removes the scoped default route that is left, and
// only it.
func TestCleanLeftovers_AfterCrash_RequireRoot(t *testing.T) {
	testutil.RequireRoot(t)
	info, dev := testNetworkInfo(t)
	added := applyTestJobs(t, info)
	before, err := route.DumpRoutes(netutil.FamilyV4, 0)
	require.NoError(t, err)

	require.NoError(t, dev.Close())
	require.Eventually(t, func() bool {
		_, err := net.InterfaceByName(info.TUNName)
		return err != nil
	}, 2*time.Second, 10*time.Millisecond, "%s goes away", info.TUNName)
	for _, a := range added {
		_, ok := dumpedRoute(t, a)
		assert.Equal(t, isScopedDefault4(a), ok,
			"only the scoped default route outlives the utun: %s", a)
	}

	var logs bytes.Buffer
	cleanLeftovers(zerolog.New(&logs), testRouteTable(t, info.PhysIfaceIndex))
	t.Logf("logs: %s", logs.String())
	assert.Contains(t, logs.String(), "removed leftover network configuration")
	_, ok := dumpedRoute(t, scopedDefaultRoute(info))
	assert.False(t, ok, "the scoped default route is removed")

	after, err := route.DumpRoutes(netutil.FamilyV4, 0)
	require.NoError(t, err)
	for _, r := range before {
		if r.Flags&unix.RTF_WASCLONED != 0 || r.Index == info.TUNIndex ||
			r.GatewayLink == info.TUNIndex || isAddedRoute(r, scopedDefaultRoute(info)) {
			continue
		}
		assert.True(t, slices.ContainsFunc(after, func(o route.TableRoute) bool {
			return sameRoute(o, r)
		}), "%s of others stays", r)
	}
}
