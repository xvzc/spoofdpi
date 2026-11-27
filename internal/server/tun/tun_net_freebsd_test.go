//go:build freebsd

package tun

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xvzc/spoofdpi/internal/route"
	"github.com/xvzc/spoofdpi/internal/server"
	"golang.org/x/sys/unix"
)

const (
	testTUNIndex  = 7
	testPhysIndex = 2
)

var (
	testDefaultDst = netip.MustParsePrefix("0.0.0.0/0")
	testTunAddr    = netip.MustParsePrefix("10.200.0.1/30")
)

// testRouteJob returns the job that adds r to fib and deletes it again.
func testRouteJob(description string, fib int, r route.TableRoute) server.NetworkJob {
	return server.NetworkJob{
		Description: description,
		Apply:       routeAddAction{FIB: fib, Route: r},
		Reset:       routeDeleteAction{FIB: fib, Route: r},
	}
}

func testTunAddressJob() server.NetworkJob {
	return server.NetworkJob{
		Description: "configure TUN interface address",
		Apply:       tunAddressAddAction{Name: "tun-spoofdpi", Addr: testTunAddr},
		Reset:       tunAddressDeleteAction{Name: "tun-spoofdpi", Addr: testTunAddr.Addr()},
	}
}

func testTunRouteJobs() []server.NetworkJob {
	var jobs []server.NetworkJob
	for _, dst := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		jobs = append(jobs, testRouteJob(
			"add CIDR route "+dst+" via TUN",
			0,
			route.TableRoute{
				Dst:         netip.MustParsePrefix(dst),
				GatewayLink: testTUNIndex,
				IfName:      "tun-spoofdpi",
				Flags:       unix.RTF_PROTO2,
			},
		))
	}
	return jobs
}

func testSubnetJob(subnet, ifName string) server.NetworkJob {
	return testRouteJob("add FIB subnet route", 3, route.TableRoute{
		Dst:         netip.MustParsePrefix(subnet),
		GatewayLink: testPhysIndex,
		IfName:      ifName,
		Flags:       unix.RTF_PROTO2,
	})
}

func testDefaultViaGatewayJob(gateway string) server.NetworkJob {
	return testRouteJob("add FIB default route", 3, route.TableRoute{
		Dst:     testDefaultDst,
		Gateway: netip.MustParseAddr(gateway),
		Flags:   unix.RTF_PROTO2,
	})
}

func testInfo() *tunNetworkInfoFreeBSD {
	return &tunNetworkInfoFreeBSD{
		FIBID:             3,
		Gateway:           netip.MustParseAddr("192.168.1.1"),
		PhysIfaceName:     "em0",
		PhysIfaceIndex:    testPhysIndex,
		PhysIfaceSubnet:   netip.MustParsePrefix("192.168.1.0/24"),
		PhysIfaceP2P:      false,
		FIBHasSubnetRoute: false,
		TUNName:           "tun-spoofdpi",
		TUNIndex:          testTUNIndex,
		TunAddr:           testTunAddr,
		RouteTargets:      mainFIBTargetsV4,
		IPv6Enabled:       false,
		HasIPv6Egress:     false,
	}
}

func TestBuildJobs_FreeBSD(t *testing.T) {
	ipv4Jobs := append(
		[]server.NetworkJob{
			testTunAddressJob(),
			testSubnetJob("192.168.1.0/24", "em0"),
			testDefaultViaGatewayJob("192.168.1.1"),
		},
		testTunRouteJobs()...)
	ipv6Job := testRouteJob("add IPv6 route 2000::/3 via TUN", 0, route.TableRoute{
		Dst:         netip.MustParsePrefix("2000::/3"),
		GatewayLink: testTUNIndex,
		IfName:      "tun-spoofdpi",
		Flags:       unix.RTF_PROTO2,
	})
	ipv6Job.Optional = true
	ipv6Job.Warning = ipv6RejectWarning

	tcs := []struct {
		name          string
		ipv6Enabled   bool
		hasIPv6Egress bool
		want          []server.NetworkJob
	}{
		{"ipv6 off without IPv6 egress", false, false, ipv4Jobs},
		{"ipv6 off with IPv6 egress adds no IPv6 route", false, true, ipv4Jobs},
		{"ipv6 on without IPv6 egress", true, false, ipv4Jobs},
		{
			"ipv6 on with IPv6 egress the IPv6 route goes last",
			true,
			true,
			append(ipv4Jobs, ipv6Job),
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			info := testInfo()
			info.IPv6Enabled = tc.ipv6Enabled
			info.HasIPv6Egress = tc.hasIPv6Egress

			assert.Equal(t, tc.want, buildJobs(info))
		})
	}
}

func TestBuildJobs_FreeBSD_NoGateway(t *testing.T) {
	fibDefaultJob := testRouteJob("add FIB default route", 3, route.TableRoute{
		Dst:         testDefaultDst,
		GatewayLink: testPhysIndex,
		IfName:      "ppp0",
		Flags:       unix.RTF_PROTO2,
	})

	tcs := []struct {
		name          string
		physIfaceCIDR string
		physIfaceP2P  bool
		want          []server.NetworkJob
	}{
		{
			"point-to-point uplink needs no FIB subnet route",
			"",
			true,
			append(
				[]server.NetworkJob{testTunAddressJob(), fibDefaultJob},
				testTunRouteJobs()...),
		},
		{
			"broadcast interface route keeps the FIB subnet route",
			"100.64.0.0/24",
			false,
			append(
				[]server.NetworkJob{
					testTunAddressJob(),
					testSubnetJob("100.64.0.0/24", "ppp0"),
					fibDefaultJob,
				},
				testTunRouteJobs()...),
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			info := testInfo()
			info.Gateway = netip.Addr{}
			info.PhysIfaceName = "ppp0"
			info.PhysIfaceSubnet = netip.Prefix{}
			if tc.physIfaceCIDR != "" {
				info.PhysIfaceSubnet = netip.MustParsePrefix(tc.physIfaceCIDR)
			}
			info.PhysIfaceP2P = tc.physIfaceP2P

			assert.Equal(t, tc.want, buildJobs(info))
		})
	}
}

// TestBuildJobs_FreeBSD_PointToPointGateway checks that a point-to-point
// uplink with a gateway keeps the FIB subnet route: its jobs are the same
// as those of any interface with a gateway.
func TestBuildJobs_FreeBSD_PointToPointGateway(t *testing.T) {
	info := testInfo()
	info.Gateway = netip.MustParseAddr("100.64.0.254")
	info.PhysIfaceName = "ppp0"
	info.PhysIfaceSubnet = netip.MustParsePrefix("100.64.0.1/32")
	info.PhysIfaceP2P = true

	want := append(
		[]server.NetworkJob{
			testTunAddressJob(),
			testSubnetJob("100.64.0.1/32", "ppp0"),
			testDefaultViaGatewayJob("100.64.0.254"),
		},
		testTunRouteJobs()...)
	assert.Equal(t, want, buildJobs(info))
}

// TestBuildJobs_FreeBSD_RoutesAreLeftovers checks that every route the jobs
// add is one CleanLeftovers would remove, once the kernel has added its own
// flags to it.
func TestBuildJobs_FreeBSD_RoutesAreLeftovers(t *testing.T) {
	for _, p2p := range []bool{false, true} {
		info := testInfo()
		info.IPv6Enabled, info.HasIPv6Egress = true, true
		if p2p {
			info.Gateway, info.PhysIfaceP2P = netip.Addr{}, true
		}
		for _, job := range buildJobs(info) {
			add, ok := job.Apply.(routeAddAction)
			if !ok {
				continue
			}
			dumped := add.Route
			dumped.Flags |= unix.RTF_UP | unix.RTF_STATIC
			if dumped.Gateway.IsValid() {
				dumped.Flags |= unix.RTF_GATEWAY
			}
			assert.True(t, isTaggedRoute(dumped), job.Description)
			if add.FIB == mainFIB {
				assert.True(t, isMainFIBRouteShape(dumped, testTUNIndex), job.Description)
			} else {
				assert.True(t, isFIBRouteShape(dumped), job.Description)
			}
			assert.Equal(t, add.Route, job.Reset.(routeDeleteAction).Route,
				"the reset deletes the route through the same gateway")
		}
	}
}

func TestCheckFIBUnused(t *testing.T) {
	loopback := route.TableRoute{
		Dst:         netip.MustParsePrefix("127.0.0.1/32"),
		GatewayLink: 1,
		Flags:       unix.RTF_UP | unix.RTF_HOST | unix.RTF_STATIC,
	}
	taggedDefault := route.TableRoute{
		Dst:     testDefaultDst,
		Gateway: netip.MustParseAddr("192.168.1.1"),
		Flags:   unix.RTF_UP | unix.RTF_GATEWAY | unix.RTF_STATIC | unix.RTF_PROTO2,
	}
	foreignDefault := taggedDefault
	foreignDefault.Flags &^= unix.RTF_PROTO2

	subnet := netip.MustParsePrefix("192.168.1.0/24")
	staticSubnet := route.TableRoute{
		Dst:         subnet,
		GatewayLink: testPhysIndex,
		Index:       testPhysIndex,
		Flags:       unix.RTF_UP | unix.RTF_STATIC,
	}
	kernelSubnet := staticSubnet
	kernelSubnet.Flags = unix.RTF_UP | unix.RTF_PINNED

	tcs := []struct {
		name   string
		routes []route.TableRoute
		subnet netip.Prefix

		wantErr string
	}{
		{"empty FIB", nil, subnet, ""},
		{"loopback route of the rc scripts", []route.TableRoute{loopback}, subnet, ""},
		{
			"tagged default route that the cleanup left",
			[]route.TableRoute{taggedDefault},
			subnet,
			"remove it with 'route -n delete default 192.168.1.1 -fib 3'",
		},
		{
			"untagged default route",
			[]route.TableRoute{loopback, foreignDefault},
			subnet,
			"FIB 3 is already in use",
		},
		{
			"static route to the physical subnet",
			[]route.TableRoute{loopback, staticSubnet},
			subnet,
			"FIB 3 is already in use: it has the route 192.168.1.0/24",
		},
		{
			"static route to the physical subnet names the delete command",
			[]route.TableRoute{staticSubnet},
			subnet,
			"route -n delete -net 192.168.1.0/24 -fib 3",
		},
		{
			"kernel route to the physical subnet",
			[]route.TableRoute{kernelSubnet},
			subnet,
			"",
		},
		{
			"static route to the subnet when no subnet job runs",
			[]route.TableRoute{staticSubnet},
			netip.Prefix{},
			"",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			err := checkFIBUnused(3, tc.routes, tc.subnet)
			if tc.wantErr != "" {
				assert.ErrorContains(t, err, tc.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHasKernelSubnetRoute(t *testing.T) {
	subnet := netip.MustParsePrefix("192.168.1.0/24")
	kernel := route.TableRoute{
		Dst:         subnet,
		GatewayLink: testPhysIndex,
		Index:       testPhysIndex,
		Flags:       unix.RTF_UP | unix.RTF_PINNED,
	}
	static := kernel
	static.Flags = unix.RTF_UP | unix.RTF_STATIC
	otherIface := kernel
	otherIface.Index = 9

	assert.True(
		t,
		hasKernelSubnetRoute([]route.TableRoute{kernel}, subnet, testPhysIndex),
	)
	assert.False(
		t,
		hasKernelSubnetRoute([]route.TableRoute{static}, subnet, testPhysIndex),
		"a static route is someone's, not the kernel's",
	)
	assert.False(
		t,
		hasKernelSubnetRoute([]route.TableRoute{otherIface}, subnet, testPhysIndex),
	)
	assert.False(t, hasKernelSubnetRoute(nil, subnet, testPhysIndex))
	assert.False(
		t,
		hasKernelSubnetRoute([]route.TableRoute{kernel}, netip.Prefix{}, testPhysIndex),
	)
}

// TestBuildJobs_FreeBSD_KernelSubnetRoute checks that with
// net.add_addr_allfibs=1, whose FIB already has the kernel's route to the
// subnet, the jobs neither add nor delete a subnet route.
func TestBuildJobs_FreeBSD_KernelSubnetRoute(t *testing.T) {
	info := testInfo()
	info.FIBHasSubnetRoute = true

	want := append(
		[]server.NetworkJob{testTunAddressJob(), testDefaultViaGatewayJob("192.168.1.1")},
		testTunRouteJobs()...)
	assert.Equal(t, want, buildJobs(info))
}

func TestCheckFIBNumber(t *testing.T) {
	assert.NoError(t, checkFIBNumber(1, 2))
	assert.NoError(t, checkFIBNumber(3, 16))

	err := checkFIBNumber(1, 1)
	assert.ErrorContains(t, err, "net.fibs")
	assert.ErrorContains(t, err, "sysctl net.fibs=2")
	assert.ErrorContains(t, checkFIBNumber(4, 4), "sysctl net.fibs=5")
	assert.Error(t, checkFIBNumber(0, 16), "FIB 0 is the main FIB")
}
