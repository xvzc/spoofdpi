// Package probe measures the hop counts to sites, so that the hop count
// spoofdpi learns, and the TTL of its fake packets, can be checked against
// the real path, and checks how a DPI on the path blocks their TLS and QUIC
// connections.
//
// For each target, a host name or IPv4 address, it measures the hop
// counts of the hops(tcp) line of its https section and the hops(udp) line
// of its quic section, on port 443, as ACTUAL / LEARNED:
//
//   - TCP ACTUAL: the smallest TTL whose SYN completes a handshake,
//     minus 1.
//   - TCP LEARNED: the hop count spoofdpi learns from the SYN/ACK of
//     a connection at the default TTL, with the same capture and estimate
//     as spoofdpi's TCP sniffer.
//   - UDP ACTUAL: the smallest TTL whose QUIC probe the server
//     answers, with a Version Negotiation packet or an ICMP port
//     unreachable, minus 1.
//   - UDP LEARNED: the hop count spoofdpi learns from the server's
//     UDP reply to the probe at the default TTL, with the same capture and
//     estimate as spoofdpi's UDP sniffer.
//
// It then runs the QUIC check of its quic section (see QUICResult):
// whether the server answers a QUIC v1 Initial for the site, compared with
// one for a benign name. Then it runs the DPI checks of its dpi subsection
// (see DPIResult): how a ClientHello is blocked, whether it gets through
// in small chunks, with spoofdpi's disorder or after spoofdpi's fake
// packets, and the hop the DPI is at. The server check of its server
// subsection (see ServerResult) then sends the fake packets so that they
// reach the server, to see whether it drops them.
//
// The learned hop counts, the hop of a DPI that blocks silently, and the
// fake and server checks need packet capture, usually root.
//
// Hop counts are numbers of routers, the unit spoofdpi learns them in. Only
// IPv4 is probed.
package probe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/dns"
)

// Options configures a probe run.
type Options struct {
	// URLs are the targets, as ParseTarget accepts them.
	URLs []string
	Config
	// DNS are the options host names are resolved with.
	DNS config.DNSOptions
	// DNSSource says where DNS comes from, such as "config /path" or "no
	// config file", for the line Run prints.
	DNSSource string
}

// maxConcurrentTargets is the number of targets probed at a time. Each
// round of a TTL scan opens a socket per TTL, so this bounds the sockets
// open at once.
const maxConcurrentTargets = 4

// deps are what run measures with; tests replace them.
type deps struct {
	resolve     resolveFunc
	dialTCP     dialFunc
	dialUDP     dialFunc
	openCapture openCaptureFunc
	// openFakes opens the fake stack; nil sends no fake packets.
	openFakes openFakesFunc
	stagger   time.Duration
	learnWait time.Duration
	// attempts returns the attempts of the DPI checks of a target; nil
	// means the real ones.
	attempts func(server netip.AddrPort, host string) attemptFunc
	// quicAttempts returns the attempt of the QUIC check of a target; nil
	// means the real one.
	quicAttempts func(server netip.AddrPort) quicAttemptFunc
	residual     residualWait
	// status shows the progress; nil shows nothing.
	status statusFunc
}

// Run probes every target and writes the report to stdout. The DNS used
// and warnings go to stderr, and, when stderr is a terminal, a status line
// rewritten in place that shows the progress. Up to maxConcurrentTargets
// targets run at a time, except that targets at the same address run one
// after another: first the hop counts of all of them, then, per target,
// its QUIC check and its DPI checks. It returns an
// error when the probe cannot run, for example because opts is invalid;
// the measurements do not change it. SIGINT, SIGTERM and SIGHUP, or
// cancelling ctx, stop the probe; Run then reports the targets that
// finished and returns an *InterruptedError.
func Run(ctx context.Context, opts Options, stdout, stderr io.Writer) error {
	dnsOpts := opts.DNS
	client := dns.NewClient(zerolog.Nop(), &dnsOpts)
	return run(ctx, opts, deps{
		resolve: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return client.Resolve(ctx, &dnsOpts, host)
		},
		dialTCP:     dialer("tcp4"),
		dialUDP:     dialer("udp4"),
		openCapture: openCapture,
		openFakes:   openFakeStack,
		stagger:     defaultStagger,
		learnWait:   defaultLearnWait,
		residual: residualWait{
			recheck: defaultResidualRecheck,
			limit:   defaultResidualLimit,
		},
		status: terminalStatus,
	}, stdout, stderr)
}

func run(ctx context.Context, opts Options, d deps, stdout, stderr io.Writer) error {
	targets, err := opts.targets()
	if err != nil {
		return err
	}
	urls := make([]string, len(targets))
	for i, t := range targets {
		urls[i] = t.Input
	}
	status := d.status
	if status == nil {
		status = noStatus
	}
	// The status is given stderr itself, to tell whether it is a
	// terminal; the lines written meanwhile go through it.
	reportProgress, lines, stopStatus := status(stderr, urls)
	defer stopStatus()
	stderr = &syncWriter{w: lines}
	_, _ = fmt.Fprintf(stderr, "probe: dns: %s\n", opts.DNSSource)

	ctx, stop := stopOnSignal(ctx)
	defer stop()
	progress := func(i int) targetProgress {
		return targetProgress{report: reportProgress, target: i}
	}

	results := make([]Result, len(targets))
	finished := make([]bool, len(targets))
	addrs := make([]netip.Addr, len(targets))

	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Go(func() {
			progress(i).phase("resolving")
			addr, note := resolveTarget(ctx, d.resolve, t)
			if note == "" {
				addrs[i] = addr
				return
			}
			if ctx.Err() == nil {
				results[i] = Result{Target: t, Addr: addr, AddrNote: note}
				finished[i] = true
				progress(i).done()
			}
		})
	}
	wg.Wait()

	p := &Prober{
		cfg:          opts.Config,
		dialTCP:      d.dialTCP,
		dialUDP:      d.dialUDP,
		stagger:      d.stagger,
		learnWait:    d.learnWait,
		sender:       newHelloSender(),
		attempts:     d.attempts,
		quicAttempts: d.quicAttempts,
		residual:     d.residual,
	}
	closeLearners := startLearners(p, d.openCapture, addrs, stderr)
	defer closeLearners()
	// The fake checks confirm their fakes in the flow capture, so they need
	// it; without it, its warning covers them.
	if p.flows != nil && d.openFakes != nil {
		p.fakes = openFakesOnce(ctx, d.openFakes, validAddrs(addrs), stderr)
	}

	slots := make(chan struct{}, maxConcurrentTargets)
	acquire := func() bool {
		select {
		case slots <- struct{}{}:
			return true
		case <-ctx.Done():
			return false
		}
	}
	probeGroup := func(group []int) {
		// The hop counts of all the targets first: the QUIC and DPI checks
		// of one can leave a residual block that would spoil the TTL scans
		// of the next.
		for _, i := range group {
			if !acquire() {
				return
			}
			progress(i).phase("hops")
			results[i] = p.Probe(ctx, targets[i], addrs[i])
			<-slots
			if ctx.Err() != nil {
				return
			}
			progress(i).phase("queued for checks")
		}
		// Then, per target, the QUIC check, which is short, before the DPI
		// checks, whose blocked ClientHellos can escalate a block.
		prevQUIC, prevTLS := "", ""
		for _, i := range group {
			t := targets[i]
			if !acquire() {
				return
			}
			results[i].QUIC = p.measureQUIC(ctx, t, addrs[i], prevQUIC, progress(i))
			if ctx.Err() != nil {
				<-slots
				return
			}
			results[i].DPI, results[i].Server = p.measureDPI(
				ctx, t, addrs[i], results[i].TCP, prevTLS, progress(i))
			<-slots
			if ctx.Err() != nil {
				return
			}
			// prevQUIC is the last target whose QUIC Initial was blocked,
			// or that a residual block skipped: it may still be there. A
			// clear target shows that it is gone.
			switch results[i].QUIC.Status {
			case QUICCensored, QUICSkipped:
				prevQUIC = t.Input
			case QUICClear:
				prevQUIC = ""
			}
			// prevTLS is the last target whose ClientHello was blocked, or
			// whose server check left a residual block: it may still be
			// there. A clear target without one shows that it is gone.
			switch block := results[i].DPI.Block; {
			case block.State == StepDone &&
				(block.Kind == BlockRST || block.Kind == BlockSilent || block.Kind == BlockOther):
				prevTLS = t.Input
			case block.State == StepDone && block.Kind == BlockClear &&
				results[i].Server.State == StepSkipped:
				prevTLS = t.Input
			case block.State == StepDone && block.Kind == BlockClear:
				prevTLS = ""
			}
			finished[i] = true
			progress(i).done()
		}
	}
	for _, group := range groupByAddr(addrs) {
		wg.Go(func() { probeGroup(group) })
	}
	wg.Wait()
	stopStatus()

	var report []Result
	for i, r := range results {
		if finished[i] {
			report = append(report, r)
		}
	}
	if err := WriteReport(stdout, report); err != nil {
		return err
	}
	if ctx.Err() != nil {
		var interrupted *InterruptedError
		if errors.As(context.Cause(ctx), &interrupted) {
			return interrupted
		}
		return &InterruptedError{}
	}
	return nil
}

// targets validates opts and returns the parsed targets.
func (opts Options) targets() ([]Target, error) {
	switch {
	case len(opts.URLs) == 0:
		return nil, errors.New("at least one --url is required")
	case opts.MaxTTL < 1 || opts.MaxTTL > 255:
		return nil, errors.New("--max-ttl must be from 1 to 255")
	case opts.Timeout <= 0:
		return nil, errors.New("--timeout must be positive")
	}
	targets := make([]Target, len(opts.URLs))
	for i, u := range opts.URLs {
		t, err := ParseTarget(u)
		if err != nil {
			return nil, fmt.Errorf("--url: %w", err)
		}
		targets[i] = t
	}
	return targets, nil
}

// validAddrs returns the valid addresses of addrs, those of the targets
// to probe.
func validAddrs(addrs []netip.Addr) []netip.Addr {
	var valid []netip.Addr
	for _, a := range addrs {
		if a.IsValid() {
			valid = append(valid, a)
		}
	}
	return valid
}

// startLearners opens the captures the targets to probe at addrs need, one
// for SYN/ACKs, one for UDP packets and one for the TCP packets of the DPI
// checks, when there is any target to probe, and sets p's learners and
// flow watch. If a capture cannot be opened, it warns once on stderr and p
// uses none. It returns a function that closes them.
func startLearners(
	p *Prober,
	open openCaptureFunc,
	addrs []netip.Addr,
	stderr io.Writer,
) (closeAll func()) {
	servers := validAddrs(addrs)

	var closers []func()
	closeAll = func() {
		for _, c := range closers {
			c()
		}
	}
	openFor := func(kind captureKind, servers []netip.Addr) (packetSource, error) {
		if len(servers) == 0 {
			return nil, nil
		}
		return open(kind, servers)
	}
	start := func(kind captureKind, parse parseFunc, servers []netip.Addr) (*learner, error) {
		src, err := openFor(kind, servers)
		if src == nil {
			return nil, err
		}
		l := newLearner(src, parse, servers)
		closers = append(closers, l.Close)
		return l, nil
	}

	tcp, err := start(captureSynAcks, parseSynAck, servers)
	var udp *learner
	if err == nil {
		udp, err = start(captureUDP, parseUDP, servers)
	}
	var flows *flowWatch
	if err == nil {
		var src packetSource
		if src, err = openFor(captureTCPFlows, servers); src != nil {
			flows = newFlowWatch(src)
			closers = append(closers, flows.Close)
		}
	}
	if err != nil {
		closeAll()
		closers = nil
		_, _ = fmt.Fprintf(
			stderr,
			"probe: warning: packet capture unavailable (%v); learned hop counts, "+
				"the silent DPI position, and the fake and server checks are "+
				"skipped; run as root\n",
			err,
		)
		return closeAll
	}
	p.tcpLearner, p.udpLearner, p.flows = tcp, udp, flows
	return closeAll
}

// openFakesOnce returns the function that opens the fake stack with open,
// for connections to servers, the first time it is called, and returns it
// or why there is none. If it cannot be opened, it warns once on stderr.
func openFakesOnce(
	ctx context.Context,
	open openFakesFunc,
	servers []netip.Addr,
	stderr io.Writer,
) func() (fakeStack, string) {
	return sync.OnceValues(func() (fakeStack, string) {
		stack, err := open(ctx, servers)
		if err == nil {
			return stack, ""
		}
		// The flow capture opened, so root can help only when the fake
		// stack's own capture did not.
		reason, hint := "fake packets unavailable", ""
		if errors.Is(err, errFakeCapture) {
			reason, hint = "needs root", "; run as root"
		}
		if ctx.Err() == nil {
			_, _ = fmt.Fprintf(
				stderr,
				"probe: warning: fake packets unavailable (%v); "+
					"the fake and server checks are skipped%s\n",
				err,
				hint,
			)
		}
		return nil, reason
	})
}

// syncWriter serializes the writes of concurrent targets.
type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (w *syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.w.Write(p)
}
