//go:build network && (darwin || freebsd || linux)

package route

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
