package desync

import (
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/packetio/capture"
)

// joinAddrPort formats ip and port as ip:port, or [ip]:port for IPv6.
func joinAddrPort(ip net.IP, port uint16) string {
	return net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
}

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

// captureWarnings are the warnings startSniffer logs when it captures
// less than asked.
type captureWarnings struct {
	// none says that nothing is learned on the interface.
	none string
	// ipv6 says that nothing is learned for IPv6 on the interface.
	ipv6 string
}

// startSniffer opens a capture handle on e and starts on it the sniffer
// that newSniffer makes for e's families. It returns the sniffer and the
// families it captures, or a nil sniffer and no families when nothing is
// captured on e, after logging warn.none. Only the failures that cost
// IPv4 are errors, which name the interface:
//
//   - A link type the filter does not support costs every family of e,
//     and is a warning.
//   - Any other failure of an interface without IPv4 is a warning.
//   - If the sniffer of both families does not start, the sniffer of IPv4
//     is tried on the same handle, after logging warn.ipv6.
//
// The handle is closed unless the sniffer starts.
func startSniffer[S Sniffer](
	logger zerolog.Logger,
	e EgressIface,
	newSniffer func(capture.Handle, netutil.FamilySet) S,
	warn captureWarnings,
) (sniffer S, learns netutil.FamilySet, err error) {
	var none S
	logger = logger.With().Str("interface", e.Iface.Name).Logger()
	ipv4 := netutil.NewFamilySet(netutil.FamilyV4)

	handle, err := newCaptureHandle(&e.Iface)
	if err != nil {
		if e.Fams.Has(netutil.FamilyV4) {
			return none, 0, fmt.Errorf("on %s: %w", e.Iface.Name, err)
		}
		logger.Warn().Err(err).Msg(warn.none)
		return none, 0, nil
	}

	fams := e.Fams
	for {
		sniffer = newSniffer(handle, fams)
		err = sniffer.StartCapturing()
		switch {
		case err == nil:
			return sniffer, fams, nil
		case errors.Is(err, capture.ErrUnsupportedLinkType),
			!fams.Has(netutil.FamilyV4):
			handle.Close()
			logger.Warn().Err(err).Msg(warn.none)
			return none, 0, nil
		case fams != ipv4:
			logger.Warn().Err(err).Msg(warn.ipv6)
			fams = ipv4
		default:
			handle.Close()
			return none, 0, fmt.Errorf("on %s: %w", e.Iface.Name, err)
		}
	}
}
