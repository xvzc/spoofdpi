// Package testutil holds helpers shared by tests.
package testutil

import (
	"os"
	"testing"
)

// RequireRoot skips t unless the test runs as root. A test that calls it
// ends its name in RequireRoot, so that the root tests run on their own
// with:
//
//	go test -exec sudo -tags network -count=1 -run RequireRoot ./internal/...
func RequireRoot(t testing.TB) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root: run with go test -exec sudo -run RequireRoot")
	}
}
