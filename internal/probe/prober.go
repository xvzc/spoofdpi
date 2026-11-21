package probe

import (
	"context"
	"net/netip"
	"sync"
	"time"
)

// hopTries is the most attempts at the default TTL, and the most rounds of
// the TTL scan, of a hop count measurement: they are cheap, and a lost
// packet would otherwise report a reachable server as unreachable, or
// raise its hop count.
const hopTries = 5

// Config sets how hard a Prober tries.
type Config struct {
	// MaxTTL is the highest TTL tried, 1 to 255.
	MaxTTL int
	// Timeout bounds each connection attempt, each wait for a UDP reply,
	// and each wait for an answer in the DPI checks.
	Timeout time.Duration
}

// Prober measures hop counts to targets, and runs the DPI checks.
type Prober struct {
	cfg     Config
	dialTCP dialFunc
	dialUDP dialFunc
	// tcpLearner and udpLearner are nil when packet capture is
	// unavailable.
	tcpLearner *learner
	udpLearner *learner
	// flows is nil when packet capture is unavailable.
	flows     *flowWatch
	stagger   time.Duration
	learnWait time.Duration

	// sender sends the ClientHellos of the DPI checks.
	sender helloSender
	// fakes returns the stack the fake and server checks send fake
	// packets with, opened on first use, or why there is none. It is nil
	// when packet capture is unavailable.
	fakes func() (fakeStack, string)
	// attempts returns the attempts of the DPI checks of a target; nil
	// means dpiAttempts.
	attempts func(server netip.AddrPort, host string) attemptFunc
	// quicAttempts returns the attempt of the QUIC check of a target; nil
	// means quicAttempt.
	quicAttempts func(server netip.AddrPort) quicAttemptFunc
	residual     residualWait
}

// Probe measures the TCP hop counts of t at addr, an IPv4 address of
// t.Host, on httpsPort, and its UDP hop counts on quicPort. The TCP and
// UDP measurements run concurrently.
func (p *Prober) Probe(ctx context.Context, t Target, addr netip.Addr) Result {
	r := Result{Target: t, Addr: addr}
	var wg sync.WaitGroup
	wg.Go(func() {
		r.TCP, r.TCPLearned = p.measureTCP(ctx, netip.AddrPortFrom(addr, httpsPort))
	})
	wg.Go(func() {
		r.UDP, r.UDPLearned = p.measureUDP(ctx, netip.AddrPortFrom(addr, quicPort))
	})
	wg.Wait()
	return r
}

// measureDPI runs the DPI checks of t at addr, an IPv4 address of t.Host,
// then the server check. tcp is the TCP hop count measured. prev is the
// URL of the target checked before at the same address, if any.
func (p *Prober) measureDPI(
	ctx context.Context,
	t Target,
	addr netip.Addr,
	tcp TCPResult,
	prev string,
	progress targetProgress,
) (DPIResult, ServerResult) {
	server := netip.AddrPortFrom(addr, httpsPort)
	attempts := p.attempts
	if attempts == nil {
		attempts = p.dpiAttempts
	}
	r := dpiRunner{
		timeout:      p.cfg.Timeout,
		hops:         dpiHops(tcp, p.cfg.MaxTTL),
		hopsMeasured: tcp.Status == TCPMeasured,
		reachedTCP:   tcp.Status == TCPMeasured || tcp.Status == TCPAboveMax,
		attempt:      attempts(server, t.Host),
		fakesReady: func() string {
			_, reason := p.fakeStack()
			return reason
		},
		canWatch: p.flows != nil,
		residual: p.residual,
		progress: progress,
	}
	res := r.run(ctx, prev)
	return res, r.server(ctx, &res)
}

// fakeStack returns the stack fake packets are sent with, or why there is
// none.
func (p *Prober) fakeStack() (fakeStack, string) {
	if p.fakes == nil {
		return nil, "needs root"
	}
	return p.fakes()
}

// dpiHops is the hop count the position check scans up to: the TCP hop
// count, or the maximum TTL when it is not known.
func dpiHops(tcp TCPResult, maxTTL int) int {
	if tcp.Status == TCPMeasured {
		return tcp.Hops
	}
	return maxTTL
}

// resolveFunc returns the addresses of host.
type resolveFunc func(ctx context.Context, host string) ([]netip.Addr, error)

// resolveTarget returns the address to probe t at: the first IPv4 address
// of its host. note says why there is none to probe; addr is then
// invalid.
func resolveTarget(
	ctx context.Context,
	resolve resolveFunc,
	t Target,
) (addr netip.Addr, note string) {
	addrs, err := resolve(ctx, t.Host)
	if err != nil {
		return netip.Addr{}, "resolve: " + err.Error()
	}
	for _, a := range addrs {
		if a = a.Unmap(); a.Is4() {
			return a, ""
		}
	}
	return netip.Addr{}, "no IPv4 address"
}

// groupByAddr groups the indexes of addrs by address, in order, skipping
// invalid addresses. Targets at the same address are probed one after
// another, so that their probes do not mix in the server's or the
// network's view, nor in the SYN/ACKs captured from it.
func groupByAddr(addrs []netip.Addr) [][]int {
	var groups [][]int
	index := map[netip.Addr]int{}
	for i, a := range addrs {
		if !a.IsValid() {
			continue
		}
		g, ok := index[a]
		if !ok {
			g = len(groups)
			index[a] = g
			groups = append(groups, nil)
		}
		groups[g] = append(groups[g], i)
	}
	return groups
}
