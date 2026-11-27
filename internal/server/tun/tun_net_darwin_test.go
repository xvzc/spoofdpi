//go:build darwin

package tun

import (
	"net/netip"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/xvzc/spoofdpi/internal/route"
	"github.com/xvzc/spoofdpi/internal/server"
	"golang.org/x/sys/unix"
)

// testInfoDarwin returns the network info of a TUN utun9 (index 30) on en0
// (index 4) with the gateway 192.168.1.1.
func testInfoDarwin() *tunNetworkInfoDarwin {
	return &tunNetworkInfoDarwin{
		Gateway:        netip.MustParseAddr("192.168.1.1"),
		PhysIfaceName:  "en0",
		PhysIfaceIndex: 4,
		TUNName:        "utun9",
		TUNIndex:       30,
		TunLocal:       netip.MustParsePrefix("10.200.0.1/30"),
		TunRemote:      netip.MustParseAddr("10.200.0.2"),
		RouteTargetCIDRs: []netip.Prefix{
			netip.MustParsePrefix("10.200.0.0/30"),
			netip.MustParsePrefix("0.0.0.0/1"),
			netip.MustParsePrefix("128.0.0.0/1"),
		},
	}
}

// utunJob returns the job of the route to dst through utun9.
func utunJob(desc, dst string) server.NetworkJob {
	r := route.TableRoute{
		Dst:         netip.MustParsePrefix(dst),
		GatewayLink: 30,
		IfName:      "utun9",
		Flags:       unix.RTF_PROTO2,
	}
	return server.NetworkJob{
		Description: desc,
		Apply:       addRouteAction{route: r},
		Reset:       deleteRouteAction{route: r},
	}
}

func TestBuildJobs_Darwin(t *testing.T) {
	scopedDefault := route.TableRoute{
		Dst:     netip.MustParsePrefix("0.0.0.0/0"),
		Gateway: netip.MustParseAddr("192.168.1.1"),
		Index:   4,
		IfName:  "en0",
		Flags:   unix.RTF_PROTO2 | unix.RTF_IFSCOPE,
	}
	ipv4Jobs := []server.NetworkJob{
		{
			Description: "configure TUN interface address",
			Apply: tunAddrAction{
				name:   "utun9",
				local:  netip.MustParsePrefix("10.200.0.1/30"),
				remote: netip.MustParseAddr("10.200.0.2"),
			},
			Reset: linkDownAction{name: "utun9"},
		},
		utunJob("add CIDR route 10.200.0.0/30 via TUN", "10.200.0.0/30"),
		utunJob("add CIDR route 0.0.0.0/1 via TUN", "0.0.0.0/1"),
		utunJob("add CIDR route 128.0.0.0/1 via TUN", "128.0.0.0/1"),
		{
			Description: "add scoped default route via physical interface",
			Apply:       addRouteAction{route: scopedDefault},
			Reset: resetScopedDefaultAction{
				logger: zerolog.Nop(),
				route:  scopedDefault,
			},
		},
	}
	ipv6Job := utunJob("add IPv6 route 2000::/3 via TUN", "2000::/3")
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
			info := testInfoDarwin()
			info.IPv6Enabled = tc.ipv6Enabled
			info.HasIPv6Egress = tc.hasIPv6Egress

			assert.Equal(t, tc.want, buildJobs(zerolog.Nop(), info))
		})
	}
}

func TestBuildJobs_Darwin_NoGateway(t *testing.T) {
	info := testInfoDarwin()
	info.Gateway = netip.Addr{}
	info.PhysIfaceName = "ppp0"
	info.PhysIfaceIndex = 7

	jobs := buildJobs(zerolog.Nop(), info)

	r := route.TableRoute{
		Dst:         netip.MustParsePrefix("0.0.0.0/0"),
		GatewayLink: 7,
		Index:       7,
		IfName:      "ppp0",
		Flags:       unix.RTF_PROTO2 | unix.RTF_IFSCOPE,
	}
	assert.Len(t, jobs, 5)
	assert.Equal(t, server.NetworkJob{
		Description: "add scoped default route via physical interface",
		Apply:       addRouteAction{route: r},
		Reset:       resetScopedDefaultAction{logger: zerolog.Nop(), route: r},
	}, jobs[4])
	assert.True(t, isOwnScopedDefaultShape(route.TableRoute{
		Dst:         r.Dst,
		GatewayLink: 7,
		Index:       7,
		Flags: r.Flags | unix.RTF_UP | unix.RTF_STATIC |
			unix.RTF_PRCLONING | unix.RTF_GLOBAL,
	}), "the leftover search recognizes the route as the kernel dumps it")
}

func TestBuildJobs_Darwin_SystemScopedDefault(t *testing.T) {
	info := testInfoDarwin()
	info.SystemScopedDefault = &route.TableRoute{
		Dst:     netip.MustParsePrefix("0.0.0.0/0"),
		Gateway: netip.MustParseAddr("192.168.1.1"),
		Index:   4,
		Flags:   unix.RTF_UP | unix.RTF_GATEWAY | unix.RTF_STATIC | unix.RTF_IFSCOPE,
	}

	jobs := buildJobs(zerolog.Nop(), info)

	assert.Len(t, jobs, 4, "no scoped default route is added or reset")
	for _, job := range jobs {
		assert.NotEqual(t, "add scoped default route via physical interface",
			job.Description)
	}
}

func TestSystemScopedDefault(t *testing.T) {
	gw := netip.MustParseAddr("172.20.0.1")
	system := route.TableRoute{
		Dst:     netip.MustParsePrefix("0.0.0.0/0"),
		Gateway: gw,
		Index:   11,
		Flags:   scopedDefaultFlags,
	}
	tagged := system
	tagged.Flags |= unix.RTF_PROTO2
	unscoped := route.TableRoute{
		Dst:     netip.MustParsePrefix("0.0.0.0/0"),
		Gateway: gw,
		Index:   11,
		Flags:   scopedDefaultFlags &^ unix.RTF_IFSCOPE,
	}
	otherIface := system
	otherIface.Index = 21

	tcs := []struct {
		name   string
		routes []route.TableRoute
		want   *route.TableRoute
	}{
		{"none", []route.TableRoute{unscoped, otherIface}, nil},
		{"untagged scoped default of the interface", []route.TableRoute{system}, &system},
		{"tagged leftover", []route.TableRoute{tagged}, nil},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, systemScopedDefault(tc.routes, 11))
		})
	}
}

func TestAddedRoutes(t *testing.T) {
	info := testInfoDarwin()
	routes := addedRoutes(buildJobs(zerolog.Nop(), info))

	assert.Equal(t, []route.TableRoute{
		tunRoute(info, netip.MustParsePrefix("10.200.0.0/30")),
		tunRoute(info, netip.MustParsePrefix("0.0.0.0/1")),
		tunRoute(info, netip.MustParsePrefix("128.0.0.0/1")),
		scopedDefaultRoute(info),
	}, routes)
}
