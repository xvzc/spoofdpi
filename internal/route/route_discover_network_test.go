//go:build network && (darwin || freebsd || linux)

package route

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/netutil"
)

func TestDiscoverRoute_MatchesRouteTo(t *testing.T) {
	path, err := RouteTo(probeDstV4)
	if err != nil {
		t.Skipf("no route to the probe destination: %v", err)
	}

	route, err := DiscoverRoute(nil)
	if !path.Gateway.IsValid() {
		require.ErrorIs(t, err, ErrNoGateway)
		t.Skip("route to the internet has no gateway")
	}
	require.NoError(t, err)
	assert.Equal(t, path.Iface.Index, route.Iface.Index)
	assert.Equal(t, path.Gateway.String(), route.Gateway.String())
	assert.NotNil(t, route.LocalIP)
}

func TestDiscoverRoute6_MatchesRouteTo(t *testing.T) {
	path, err := RouteTo(probeDstV6)
	if errors.Is(err, ErrNoIPv6Route) {
		t.Skipf("no IPv6 route: %v", err)
	}
	require.NoError(t, err)

	route, err := DiscoverRoute6(nil, "")
	require.NoError(t, err)
	assert.Equal(t, netutil.FamilyV6, route.Family)
	assert.Equal(t, path.Iface.Index, route.Iface.Index)
	assert.Equal(t, path.Gateway.String(), route.Gateway.String())
	assert.Equal(t, path.Zone, route.Zone)
}

func TestDiscoverInterface_MatchesRouteTo(t *testing.T) {
	path, err := RouteTo(probeDstV4)
	if err != nil {
		t.Skipf("no route to the probe destination: %v", err)
	}

	iface, localIP, err := DiscoverInterface()
	require.NoError(t, err)
	assert.Equal(t, path.Iface.Index, iface.Index)
	assert.NotNil(t, localIP.To4())
}
