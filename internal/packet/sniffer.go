package packet

import (
	"net"

	"github.com/xvzc/spoofdpi/internal/config"
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

// HopPolicy turns a cached hop count into the TTL of fake packets.
type HopPolicy struct {
	Default uint8 // hop count assumed until it is learned
	Min     uint8 // lower bound of the hop count
	Max     uint8 // upper bound of the hop count; 0 means no bound
	Offset  int8  // added to a learned hop count
}

// NewHopPolicy builds a HopPolicy from the connection options.
func NewHopPolicy(o config.ConnOptions) HopPolicy {
	return HopPolicy{
		Default: o.HopCountDefault,
		Min:     o.HopCountMin,
		Max:     o.HopCountMax,
		Offset:  o.HopCountOffset,
	}
}

// TTL returns the TTL for fake packets to a server whose cache entry is e
// (ok is false if the server is not cached): the hop count, with Offset
// added if it was learned, clamped to [Min, Max], minus 1. The result is
// at least 1.
func (p HopPolicy) TTL(e HopEntry, ok bool) uint8 {
	hops := 255
	if ok {
		hops = int(e.Hops)
		if e.Learned {
			hops += int(p.Offset)
		}
	}
	upper := int(p.Max)
	if upper == 0 {
		upper = 255
	}
	hops = min(max(hops, int(p.Min)), upper)
	hops = min(max(hops, 2), 255)

	return uint8(hops - 1)
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
