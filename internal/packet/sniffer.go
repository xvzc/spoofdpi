package packet

// Sniffer captures packets in the background and records the hop counts
// they reveal in a HopStore.
type Sniffer interface {
	// StartCapturing installs the sniffer's capture filter and starts
	// reading packets. It fails, without reading, if the filter cannot be
	// installed: the handle would then pass every packet up.
	StartCapturing() error
}

// HopPolicy turns a hop count estimate into the TTL of fake packets.
type HopPolicy struct {
	Default uint8 // hop count assumed until it is learned
	Min     uint8 // lower bound of the hop count
	Max     uint8 // upper bound of the hop count; 0 means no bound
	Offset  int8  // added to the bounded hop count, learned or Default
}

// Hops returns the hop count that the TTL for est starts from: the learned
// one, or Default if none was learned.
func (p HopPolicy) Hops(est HopEstimate) uint8 {
	if est.Learned() {
		return est.Hops
	}
	return p.Default
}

// TTL returns the TTL for fake packets to a server whose hop count
// estimate is est: its hop count (see Hops) clamped to [Min, Max], plus
// Offset. The result is between 1 and 255.
//
// The bounds apply before Offset, so that they bound the hop count, not
// the TTL: with the default Offset of -1, the TTL stays one below them.
func (p HopPolicy) TTL(est HopEstimate) uint8 {
	upper := int(p.Max)
	if upper == 0 {
		upper = 255
	}
	hops := min(max(int(p.Hops(est)), int(p.Min)), upper)

	return uint8(min(max(hops+int(p.Offset), 1), 255))
}
