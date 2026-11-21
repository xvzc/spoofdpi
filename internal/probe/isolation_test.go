package probe

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestImportIsolation keeps probe independent of the server: it measures
// with its own sockets and its own capture, and sends ClientHellos with
// spoofdpi's desyncer, not through a running server.
func TestImportIsolation(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go command not found")
	}
	out, err := exec.Command(goBin, "list", "-deps", ".").Output()
	require.NoError(t, err)

	deps := strings.Fields(string(out))
	for _, pkg := range []string{
		"internal/server", "internal/livetest",
	} {
		for _, dep := range deps {
			assert.False(t,
				strings.HasPrefix(dep, "github.com/xvzc/spoofdpi/"+pkg),
				"probe imports %s", dep)
		}
	}
	assert.Contains(t, deps, "github.com/xvzc/spoofdpi/internal/probe")
}
