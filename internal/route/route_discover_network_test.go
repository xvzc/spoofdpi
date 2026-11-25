//go:build network && (darwin || freebsd || linux)

package route

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/netutil"
)

func TestResolveGateway_MatchesLookup(t *testing.T) {
	path, err := Lookup(probeDstV4)
	if err != nil {
		t.Skipf("no route to the probe destination: %v", err)
	}

	route, err := ResolveGateway(nil)
	if !path.Gateway.IsValid() {
		require.ErrorIs(t, err, ErrNoGateway)
		t.Skip("route to the internet has no gateway")
	}
	require.NoError(t, err)
	assert.Equal(t, path.Iface.Index, route.Iface.Index)
	assert.Equal(t, path.Gateway.String(), route.Gateway.String())
	assert.NotNil(t, route.LocalIP)
}

func TestResolveGateway6_MatchesLookup(t *testing.T) {
	path, err := Lookup(probeDstV6)
	if errors.Is(err, ErrNoIPv6) {
		t.Skipf("no IPv6 route: %v", err)
	}
	require.NoError(t, err)

	route, err := ResolveGateway6(nil, "")
	require.NoError(t, err)
	assert.Equal(t, netutil.FamilyV6, route.Family)
	assert.Equal(t, path.Iface.Index, route.Iface.Index)
	assert.Equal(t, path.Gateway.String(), route.Gateway.String())
	assert.Equal(t, path.Zone, route.Zone)
}

func TestInternetInterface_MatchesLookup(t *testing.T) {
	path, err := Lookup(probeDstV4)
	if err != nil {
		t.Skipf("no route to the probe destination: %v", err)
	}

	iface, localIP, err := InternetInterface()
	require.NoError(t, err)
	assert.Equal(t, path.Iface.Index, iface.Index)
	assert.NotNil(t, localIP.To4())
}
