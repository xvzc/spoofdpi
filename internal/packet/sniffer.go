package packet

// Sniffer captures packets in the background and records the hop counts
// they reveal in a HopStore.
type Sniffer interface {
	StartCapturing()
}

// HopPolicy turns a hop count estimate into the TTL of fake packets.
type HopPolicy struct {
	Default uint8 // hop count assumed until it is learned
	Min     uint8 // lower bound of the hop count
	Max     uint8 // upper bound of the hop count; 0 means no bound
	Offset  int8  // added to a learned hop count
}

// Hops returns the hop count that the TTL for est starts from: the learned
// one, Default if none was learned, or 255 if the server is not in the
// store.
func (p HopPolicy) Hops(est HopEstimate) uint8 {
	switch {
	case est.Learned():
		return est.Hops
	case est.Source == HopSourceDefault:
		return p.Default
	default:
		return 255
	}
}

// TTL returns the TTL for fake packets to a server whose hop count
// estimate is est: the learned hop count plus Offset, or Default if it was
// not learned, or 255 if the server is not in the store, clamped to
// [Min, Max], minus 1. The result is at least 1.
func (p HopPolicy) TTL(est HopEstimate) uint8 {
	hops := int(p.Hops(est))
	if est.Learned() {
		hops += int(p.Offset)
	}
	upper := int(p.Max)
	if upper == 0 {
		upper = 255
	}
	hops = min(max(hops, int(p.Min)), upper)
	hops = min(max(hops, 2), 255)

	return uint8(hops - 1)
}
