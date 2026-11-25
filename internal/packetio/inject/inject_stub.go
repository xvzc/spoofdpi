//go:build !darwin && !freebsd && !linux

package inject

import (
	"fmt"
	"runtime"

	"github.com/xvzc/spoofdpi/internal/netutil"
)

// Open fails where spoofdpi cannot send raw IP packets.
func Open(fam netutil.Family, _ Options) (Sender, error) {
	return nil, fmt.Errorf("open %v sender: not supported on %s", fam, runtime.GOOS)
}
