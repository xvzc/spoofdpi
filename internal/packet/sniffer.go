package packet

import (
	"net"

	"github.com/xvzc/spoofdpi/internal/netutil"
)

type Sniffer interface {
	StartCapturing()
	Register(addrs []net.IP)
	// Hops returns the hop-count cache entry of key, and whether key is
	// cached (registered or learned).
	Hops(key netutil.IPKey) (e HopEntry, ok bool)
}

// HopPolicy turns a cached hop count into the TTL of fake packets.
type HopPolicy struct {
	Default uint8 // hop count assumed until it is learned
	Min     uint8 // lower bound of the hop count
	Max     uint8 // upper bound of the hop count; 0 means no bound
	Offset  int8  // added to a learned hop count
}

// TTL returns the TTL for fake packets to a server whose cache entry is e
// (ok is false if the server is not cached): the learned hop count plus
// Offset, or Default if it was not learned, clamped to [Min, Max], minus
// 1. The result is at least 1.
func (p HopPolicy) TTL(e HopEntry, ok bool) uint8 {
	hops := 255
	if ok {
		hops = int(p.Default)
		if e.Learned {
			hops = int(e.Hops) + int(p.Offset)
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
	Hops    uint8 // the learned hop count; 0 until Learned
	Learned bool  // learned from a captured packet, not only registered
}
