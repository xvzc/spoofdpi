package desync

import (
	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/packetio/capture"
)

// UDPStack is what fake UDP packets are sent with: sniffers that learn hop
// counts, and a writer that sends crafted packets through its senders.
type UDPStack struct {
	// Sniffers are the sniffers of the interfaces whose capture handles
	// work, one per interface.
	Sniffers []*UDPSniffer
	Writer   *UDPWriter
}

// OpenUDPStack opens a capture handle on each of ifaces for a sniffer of
// the families of that interface, which records hop counts in hops,
// starts the sniffers, which log under the trace ID runID, and makes a
// writer that sends packets through senders. Each interface must appear
// once in ifaces. The handles stay open for the life of the process: the
// sniffers read them until then.
//
// A family whose packets cannot be captured is not learned: its fake
// packets use the default hop count. Only IPv4 must be captured:
//
//   - On a link type the capture filter does not support, the handle is
//     closed with a warning, whatever its families.
//   - Any other failure to open or start the handle of an interface
//     without IPv4 is a warning; a handle that opened is closed.
//   - If the sniffer of an interface of both families does not start, the
//     sniffer of IPv4 alone is started on it, with a warning.
//
// The other handles are kept. OpenUDPStack fails if the handle of IPv4
// cannot be opened or its sniffer cannot start, with an error that names
// the interface; the sniffers already started keep their handles, as the
// error is meant to end the process.
func OpenUDPStack(
	runID string,
	logger zerolog.Logger,
	ifaces []EgressIface,
	senders Senders,
	hops *HopStore,
) (*UDPStack, error) {
	stack := &UDPStack{Writer: NewUDPWriter(logger, senders)}
	newSniffer := func(h capture.Handle, fams netutil.FamilySet) *UDPSniffer {
		return NewUDPSniffer(runID, logger, h, fams, hops)
	}
	for _, e := range ifaces {
		sniffer, _, err := startSniffer(logger, e, newSniffer, udpCaptureWarnings)
		if err != nil {
			return nil, err
		}
		if sniffer != nil {
			stack.Sniffers = append(stack.Sniffers, sniffer)
		}
	}
	return stack, nil
}

// udpCaptureWarnings are the warnings of the families that a UDP stack
// does not capture.
var udpCaptureWarnings = captureWarnings{
	none: "hop counts are not learned on this interface; " +
		"fake packets use hop-count-default",
	ipv6: "hop counts are not learned for IPv6 on this interface; " +
		"IPv6 fake packets use hop-count-default",
}
