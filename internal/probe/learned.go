package probe

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/xvzc/spoofdpi/internal/capture"
	"github.com/xvzc/spoofdpi/internal/netutil"
)

const (
	// captureReadTimeout bounds how long the capture reader takes to see
	// that it is stopped.
	captureReadTimeout = 100 * time.Millisecond
	// defaultLearnWait is how long a measurement waits for the captured
	// SYN/ACK or UDP reply of its baseline attempt after the attempt
	// reaches the server.
	defaultLearnWait = 500 * time.Millisecond
)

// captureKind selects the packets a capture keeps: those spoofdpi's TCP
// or UDP sniffer learns hop counts from, or the TCP packets of the DPI
// checks.
type captureKind int

const (
	// captureSynAcks keeps IPv4 TCP SYN/ACKs.
	captureSynAcks captureKind = iota
	// captureUDP keeps IPv4 UDP packets.
	captureUDP
	// captureTCPFlows keeps IPv4 TCP packets from and to the servers.
	captureTCPFlows
)

// packetSource is the part of a capture.Handle the learner reads from.
type packetSource interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	LinkType() layers.LinkType
	Close()
}

// openCaptureFunc opens a packet source of the given kind, for the given
// servers.
type openCaptureFunc func(kind captureKind, servers []netip.Addr) (packetSource, error)

// openCapture opens a capture on the interface of the default route, the
// one spoofdpi captures on without --gateway. Its BPF filter is that of
// spoofdpi's sniffer for kind, or for captureTCPFlows one that keeps the
// TCP packets of the servers.
func openCapture(kind captureKind, servers []netip.Addr) (packetSource, error) {
	filter := capture.SynAckFilter
	switch kind {
	case captureUDP:
		filter = capture.UDPFilter
	case captureTCPFlows:
		hosts := make([]net.IP, len(servers))
		for i, s := range servers {
			hosts[i] = s.AsSlice()
		}
		filter = func(linkType layers.LinkType) ([]capture.BPFInstruction, error) {
			return capture.TCPHostFilter(linkType, hosts)
		}
	}
	iface, _, err := netutil.DiscoverInterface()
	if err != nil {
		return nil, err
	}
	h, err := capture.NewHandleWithReadTimeout(iface, captureReadTimeout)
	if err != nil {
		return nil, err
	}
	prog, err := filter(h.LinkType())
	if err != nil {
		h.Close()
		return nil, fmt.Errorf("capture filter: %w", err)
	}
	if err := h.SetBPFRawInstructionFilter(prog); err != nil {
		h.Close()
		return nil, fmt.Errorf("set capture filter: %w", err)
	}
	return h, nil
}

// observation is a captured SYN/ACK or UDP packet.
type observation struct {
	src           netip.AddrPort
	dstPort       uint16
	ttlLeft, hops uint8
}

// parseFunc returns the observation of a packet spoofdpi learns a hop
// count from. ok is false for any other packet, and for one not sent over
// IPv4, as spoofdpi learns hop counts over IPv4 only.
type parseFunc func(p gopacket.Packet) (o observation, ok bool)

// parseSynAck parses a SYN/ACK as spoofdpi's TCP sniffer does.
func parseSynAck(p gopacket.Packet) (observation, bool) {
	sa, ok := capture.ParseSynAck(p)
	if !ok {
		return observation{}, false
	}
	return newObservation(sa.Src, sa.SrcPort, sa.DstPort, sa.TTLLeft, sa.Hops)
}

// parseUDP parses a UDP packet as spoofdpi's UDP sniffer does.
func parseUDP(p gopacket.Packet) (observation, bool) {
	u, ok := capture.ParseUDP(p)
	if !ok {
		return observation{}, false
	}
	return newObservation(u.Src, u.SrcPort, u.DstPort, u.TTLLeft, u.Hops)
}

func newObservation(
	src net.IP,
	srcPort, dstPort uint16,
	ttlLeft, hops uint8,
) (observation, bool) {
	addr, ok := netip.AddrFromSlice(src.To4())
	if !ok {
		return observation{}, false
	}
	return observation{
		src:     netip.AddrPortFrom(addr, srcPort),
		dstPort: dstPort,
		ttlLeft: ttlLeft,
		hops:    hops,
	}, true
}

// learner reads packets from a packet source and keeps those from the
// probed servers that spoofdpi learns hop counts from, with the hop count
// it estimates from each.
type learner struct {
	src     packetSource
	parse   parseFunc
	servers map[netip.Addr]bool
	stopped atomic.Bool
	done    chan struct{}

	mu   sync.Mutex
	seen []observation
	// added is closed, and replaced, when an observation is added.
	added   chan struct{}
	readErr error
}

// newLearner starts reading from src, keeping the packets parse accepts
// from the given servers. Close stops it and closes src.
func newLearner(src packetSource, parse parseFunc, servers []netip.Addr) *learner {
	l := &learner{
		src:     src,
		parse:   parse,
		servers: map[netip.Addr]bool{},
		done:    make(chan struct{}),
		added:   make(chan struct{}),
	}
	for _, a := range servers {
		l.servers[a] = true
	}
	go l.read()
	return l
}

func (l *learner) read() {
	defer close(l.done)
	linkType := l.src.LinkType()
	for !l.stopped.Load() {
		data, _, err := l.src.ReadPacketData()
		if err != nil {
			if capture.IsReadTimeout(err) {
				continue
			}
			l.mu.Lock()
			l.readErr = fmt.Errorf("capture stopped: %w", err)
			l.mu.Unlock()
			return
		}
		o, ok := l.parse(gopacket.NewPacket(data, linkType, gopacket.Default))
		if !ok || !l.servers[o.src.Addr()] {
			continue
		}
		l.mu.Lock()
		l.seen = append(l.seen, o)
		close(l.added)
		l.added = make(chan struct{})
		l.mu.Unlock()
	}
}

// mark returns a position in the observations, for hopsSince.
func (l *learner) mark() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.seen)
}

// await waits up to wait for a packet from server to localPort, and
// returns the latest one.
func (l *learner) await(
	ctx context.Context,
	server netip.AddrPort,
	localPort uint16,
	wait time.Duration,
) (observation, bool) {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		l.mu.Lock()
		// The latest one wins, as in spoofdpi.
		for _, o := range slices.Backward(l.seen) {
			if o.src == server && o.dstPort == localPort {
				l.mu.Unlock()
				return o, true
			}
		}
		added := l.added
		l.mu.Unlock()

		select {
		case <-added:
		case <-timer.C:
			return observation{}, false
		case <-ctx.Done():
			return observation{}, false
		}
	}
}

// hopsSince returns the distinct hop counts of the packets from server
// observed since mark, in ascending order.
func (l *learner) hopsSince(mark int, server netip.AddrPort) []uint8 {
	l.mu.Lock()
	defer l.mu.Unlock()
	var hops []uint8
	for _, o := range l.seen[mark:] {
		if o.src == server && !slices.Contains(hops, o.hops) {
			hops = append(hops, o.hops)
		}
	}
	slices.Sort(hops)
	return hops
}

// err returns the error that stopped the capture, if any.
func (l *learner) err() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.readErr
}

// Close stops reading and closes the packet source. The reader sees the
// stop within one read timeout; the source is closed only after it has
// returned, since closing it under a blocked read is not safe.
func (l *learner) Close() {
	l.stopped.Store(true)
	<-l.done
	l.src.Close()
}
