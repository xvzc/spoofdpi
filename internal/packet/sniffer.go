package packet

import (
	"net"

	"github.com/xvzc/spoofdpi/internal/netutil"
)

type Sniffer interface {
	StartCapturing()
	Register(addrs []net.IP)
	GetOptimalTTL(key netutil.IPKey) uint8
	// LearnedHops returns the hop count for key and whether it has been
	// learned from a captured packet, rather than being the registered
	// default.
	LearnedHops(key netutil.IPKey) (hops uint8, ok bool)
}

// HopEntry is a hop-count cache entry.
type HopEntry struct {
	Hops    uint8
	Learned bool // learned from a captured packet, not the default
}

// estimateHops estimates the number of hops based on TTL, assuming the
// sender started from the nearest common initial TTL (64, 128 or 255).
// This logic is based on the hop counting mechanism from GoodbyeDPI.
// It returns 0 when the TTL is unchanged, i.e. the sender is on the local
// link.
func estimateHops(ttlLeft uint8) uint8 {
	// Unrecognizable initial TTL
	estimatedInitialHops := uint8(255)
	switch {
	case ttlLeft <= 64:
		estimatedInitialHops = 64
	case ttlLeft <= 128:
		estimatedInitialHops = 128
	default:
		estimatedInitialHops = 255
	}

	return estimatedInitialHops - ttlLeft
}
