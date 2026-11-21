package probe

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hosts resolves the host names of a test to fixed addresses.
func hosts(m map[string]string) resolveFunc {
	return func(ctx context.Context, host string) ([]netip.Addr, error) {
		a, ok := m[host]
		if !ok {
			return nil, errors.New("no such host")
		}
		return []netip.Addr{netip.MustParseAddr(a)}, nil
	}
}

func noCapture(captureKind, []netip.Addr) (packetSource, error) {
	return nil, errors.New("permission denied")
}

// clearPath answers every attempt of the DPI checks as a path without
// DPI.
func clearPath(netip.AddrPort, string) attemptFunc {
	return func(context.Context, attempt) outcome { return outcome{kind: outPass} }
}

// clearQUIC answers every Initial of the QUIC check as a path without
// DPI.
func clearQUIC(netip.AddrPort) quicAttemptFunc {
	return func(context.Context, string) quicAttemptResult {
		return quicAttemptResult{outcome: quicReply}
	}
}

// testDeps returns deps on a path without DPI. A nil dialUDP is a server
// whose UDP port is closed.
func testDeps(resolve resolveFunc, dialTCP, dialUDP dialFunc) deps {
	if dialUDP == nil {
		dialUDP = refusedUDP
	}
	return deps{
		resolve:      resolve,
		dialTCP:      dialTCP,
		dialUDP:      dialUDP,
		openCapture:  noCapture,
		learnWait:    100 * time.Millisecond,
		attempts:     clearPath,
		quicAttempts: clearQUIC,
		residual: residualWait{
			recheck: 10 * time.Millisecond,
			limit:   50 * time.Millisecond,
		},
	}
}

func testOptions(urls ...string) Options {
	return Options{
		URLs:      urls,
		Config:    Config{MaxTTL: 16, Timeout: time.Second},
		DNSSource: "udp (192.0.2.53:53), no config file",
	}
}

const captureWarning = "probe: warning: packet capture unavailable (permission denied); " +
	"learned hop counts, the silent DPI position, and the fake and server checks " +
	"are skipped; run as root"

func TestRun(t *testing.T) {
	d := testDeps(
		hosts(map[string]string{"a.test": "203.0.113.1", "b.test": "203.0.113.2"}),
		fakeTCP(7, nil), refusedUDP)

	var stdout, stderr bytes.Buffer
	err := run(context.Background(),
		testOptions("a.test", "b.test", "missing.test"),
		d, &stdout, &stderr)
	require.NoError(t, err)

	block := func(url string) string {
		return "" +
			url + "\n" +
			"  https\n" +
			"    status      clear\n" +
			"    hops(tcp)   6 actual / -\n" +
			"    server      unknown (needs root)\n" +
			"  quic\n" +
			"    status      clear\n" +
			"    hops(udp)   0 actual / - (not learned)\n"
	}
	assert.Equal(t, ""+
		block("a.test (203.0.113.1)")+
		"\n"+
		block("b.test (203.0.113.2)")+
		"\n"+
		"missing.test (resolve failed: no such host)\n",
		stdout.String())

	lines := strings.Split(strings.TrimSpace(stderr.String()), "\n")
	assert.Equal(t, "probe: dns: udp (192.0.2.53:53), no config file", lines[0])
	assert.Equal(t, captureWarning, lines[1])
	assert.Len(t, lines, 2, "no per-target lines on stderr")
}

func TestRun_CaptureKinds(t *testing.T) {
	tcs := []struct {
		urls []string
		want []captureKind
	}{
		{
			urls: []string{"a.test"},
			want: []captureKind{captureSynAcks, captureUDP, captureTCPFlows},
		},
		{urls: []string{"missing.test"}},
	}
	for _, tc := range tcs {
		t.Run(strings.Join(tc.urls, ","), func(t *testing.T) {
			d := testDeps(hosts(map[string]string{"a.test": "203.0.113.1"}),
				fakeTCP(1, nil), refusedUDP)
			var (
				opened  []captureKind
				sources []*fakeSource
			)
			d.openCapture = func(kind captureKind, _ []netip.Addr) (packetSource, error) {
				opened = append(opened, kind)
				src := newFakeSource(t)
				sources = append(sources, src)
				return src, nil
			}
			opts := testOptions(tc.urls...)
			opts.MaxTTL = 2
			var stdout, stderr bytes.Buffer
			require.NoError(t, run(context.Background(), opts, d, &stdout, &stderr))
			assert.Equal(t, tc.want, opened)
			for _, src := range sources {
				assert.True(t, src.closed.Load(), "the capture is closed")
			}
			assert.NotContains(t, stderr.String(), "warning")
		})
	}
}

func TestRun_CaptureWarnsOnce(t *testing.T) {
	d := testDeps(hosts(map[string]string{
		"a.test": "203.0.113.1", "a-alias.test": "203.0.113.1",
	}), fakeTCP(5, nil), refusedUDP)
	tcpSrc := newFakeSource(t)
	d.openCapture = func(kind captureKind, _ []netip.Addr) (packetSource, error) {
		if kind == captureSynAcks {
			return tcpSrc, nil
		}
		return nil, errors.New("permission denied")
	}

	var stdout, stderr bytes.Buffer
	require.NoError(t, run(context.Background(),
		testOptions("a.test", "a-alias.test"), d, &stdout, &stderr))
	assert.Equal(t, 1, strings.Count(stderr.String(), "warning"))
	assert.Contains(t, stderr.String(), captureWarning+"\n")
	assert.True(t, tcpSrc.closed.Load(), "the capture that opened is closed")
	assert.NotContains(t, stdout.String(), "captured", "no learner is used")
}

// vnConn is a connected UDP socket to a server that answers every probe
// with a Version Negotiation packet.
type vnConn struct {
	net.Conn
	local *net.UDPAddr
	mu    sync.Mutex
	req   []byte
}

func (c *vnConn) LocalAddr() net.Addr               { return c.local }
func (c *vnConn) Close() error                      { return nil }
func (c *vnConn) SetReadDeadline(_ time.Time) error { return nil }

func (c *vnConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.req = bytes.Clone(b)
	return len(b), nil
}

func (c *vnConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return copy(b, answerVN(c.req)[1]), nil
}

// fakeUDP returns a dialFunc whose probes the server answers at the
// default TTL, and at TTL minTTL and above. Lower TTLs fail as macOS
// reports an ICMP time exceeded.
func fakeUDP(minTTL int) dialFunc {
	return func(ctx context.Context, ttl int, addr netip.AddrPort) (net.Conn, error) {
		port := 50000 + int(localPorts.Add(1))
		conn := &vnConn{local: &net.UDPAddr{IP: localIP, Port: port}}
		if ttl != 0 && ttl < minTTL {
			return unreachableConn{conn}, nil
		}
		return conn, nil
	}
}

func TestRun_Learned(t *testing.T) {
	tcpSrc, udpSrc := newFakeSource(t), newFakeSource(t)
	d := testDeps(hosts(map[string]string{"a.test": "203.0.113.1"}), nil, nil)
	d.openCapture = func(kind captureKind, _ []netip.Addr) (packetSource, error) {
		switch kind {
		case captureUDP:
			return udpSrc, nil
		case captureSynAcks:
			return tcpSrc, nil
		}
		return newFakeSource(t), nil
	}
	tcp := fakeTCP(5, nil)
	d.dialTCP = func(ctx context.Context, ttl int, addr netip.AddrPort) (net.Conn, error) {
		conn, err := tcp(ctx, ttl, addr)
		if err == nil && ttl == 0 {
			tcpSrc.frames <- synAck(t, addr, uint16(conn.LocalAddr().(*net.TCPAddr).Port), 50)
		}
		return conn, err
	}
	udp := fakeUDP(7)
	d.dialUDP = func(ctx context.Context, ttl int, addr netip.AddrPort) (net.Conn, error) {
		conn, err := udp(ctx, ttl, addr)
		if err == nil && ttl == 0 {
			udpSrc.frames <- udpFrame(t, addr, uint16(conn.LocalAddr().(*net.UDPAddr).Port), 58)
		}
		return conn, err
	}

	var stdout, stderr bytes.Buffer
	require.NoError(
		t,
		run(context.Background(), testOptions("a.test"), d, &stdout, &stderr),
	)
	assert.Contains(
		t,
		stdout.String(),
		"    hops(tcp)   4 actual / 14 learned (gap +10)\n",
	)
	assert.Contains(t, stdout.String(), "    hops(udp)   6 actual / 6 learned\n")
	assert.True(t, tcpSrc.closed.Load(), "the SYN/ACK capture is closed")
	assert.True(t, udpSrc.closed.Load(), "the UDP capture is closed")
	assert.NotContains(t, stderr.String(), "warning")
}

// slowDial delays every dial of inner long enough for the other targets
// to start.
func slowDial(inner dialFunc) dialFunc {
	return func(ctx context.Context, ttl int, addr netip.AddrPort) (net.Conn, error) {
		time.Sleep(20 * time.Millisecond)
		return inner(ctx, ttl, addr)
	}
}

func TestRun_SameAddressRunsSerially(t *testing.T) {
	d := testDeps(hosts(map[string]string{
		"a.test": "203.0.113.1", "a-alias.test": "203.0.113.1", "b.test": "203.0.113.2",
	}), slowDial(fakeTCP(3, nil)), nil)
	var rec recordedStatus
	d.status = rec.start

	var stdout, stderr bytes.Buffer
	opts := testOptions("a.test", "b.test", "a-alias.test")
	opts.MaxTTL = 4
	require.NoError(t, run(context.Background(), opts, d, &stdout, &stderr))

	assert.Less(t, rec.index(0, "queued for checks"), rec.index(2, "hops"),
		"the hops of targets at the same address do not overlap")
	assert.Less(t, rec.index(1, "hops"), rec.index(0, "queued for checks"),
		"targets at different addresses run concurrently")

	// Blocks stay in input order.
	out := stdout.String()
	assert.Less(t, strings.Index(out, "a.test ("), strings.Index(out, "b.test ("))
	assert.Less(t, strings.Index(out, "b.test ("), strings.Index(out, "a-alias.test ("))
}

func TestRun_AtMostFourTargetsAtOnce(t *testing.T) {
	var (
		mu         sync.Mutex
		active     = map[netip.Addr]int{}
		maxTargets int
	)
	tcp := fakeTCP(1, nil)
	addrs := map[string]string{}
	var urls []string
	for i := range 8 {
		host := fmt.Sprintf("t%d.test", i)
		addrs[host] = fmt.Sprintf("203.0.113.%d", i+1)
		urls = append(urls, host)
	}
	d := testDeps(
		hosts(addrs),
		func(ctx context.Context, ttl int, addr netip.AddrPort) (net.Conn, error) {
			mu.Lock()
			active[addr.Addr()]++
			maxTargets = max(maxTargets, len(active))
			mu.Unlock()
			defer func() {
				mu.Lock()
				if active[addr.Addr()]--; active[addr.Addr()] == 0 {
					delete(active, addr.Addr())
				}
				mu.Unlock()
			}()
			// Long enough for the other targets to start.
			time.Sleep(20 * time.Millisecond)
			return tcp(ctx, ttl, addr)
		},
		nil,
	)

	opts := testOptions(urls...)
	opts.MaxTTL = 2
	var stdout, stderr bytes.Buffer
	require.NoError(t, run(context.Background(), opts, d, &stdout, &stderr))

	assert.LessOrEqual(t, maxTargets, maxConcurrentTargets)
	assert.Greater(t, maxTargets, 1, "targets run concurrently")
	out := stdout.String()
	for i := 1; i < len(urls); i++ {
		assert.Less(t, strings.Index(out, urls[i-1]+" "), strings.Index(out, urls[i]+" "),
			"blocks stay in input order")
	}
}

func TestRun_Interrupted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var blocked atomic.Bool
	fast := fakeTCP(1, nil)
	d := testDeps(
		hosts(map[string]string{"fast.test": "203.0.113.1", "slow.test": "203.0.113.2"}),
		func(ctx context.Context, ttl int, addr netip.AddrPort) (net.Conn, error) {
			if addr.Addr() == netip.MustParseAddr("203.0.113.1") {
				return fast(ctx, ttl, addr)
			}
			if blocked.CompareAndSwap(false, true) {
				time.AfterFunc(200*time.Millisecond, cancel)
			}
			<-ctx.Done()
			return nil, ctx.Err()
		},
		nil,
	)

	opts := testOptions("fast.test", "slow.test", "missing.test")
	opts.Timeout = time.Minute
	var stdout, stderr bytes.Buffer
	start := time.Now()
	err := run(ctx, opts, d, &stdout, &stderr)
	assert.Less(t, time.Since(start), 5*time.Second)

	var interrupted *InterruptedError
	require.ErrorAs(t, err, &interrupted)
	assert.Nil(t, interrupted.Signal)
	assert.Equal(t, ""+
		"fast.test (203.0.113.1)\n"+
		"  https\n"+
		"    status      clear\n"+
		"    hops(tcp)   0 actual / -\n"+
		"    server      unknown (needs root)\n"+
		"  quic\n"+
		"    status      clear\n"+
		"    hops(udp)   0 actual / - (not learned)\n"+
		"\n"+
		"missing.test (resolve failed: no such host)\n",
		stdout.String(), "the unfinished target has no block")
}

func TestOptions_Targets(t *testing.T) {
	tcs := []struct {
		name    string
		modify  func(*Options)
		wantErr string
	}{
		{
			name:    "no url",
			modify:  func(o *Options) { o.URLs = nil },
			wantErr: "at least one --url is required",
		},
		{
			name:    "max-ttl 0",
			modify:  func(o *Options) { o.MaxTTL = 0 },
			wantErr: "--max-ttl must be from 1 to 255",
		},
		{
			name:    "max-ttl 256",
			modify:  func(o *Options) { o.MaxTTL = 256 },
			wantErr: "--max-ttl must be from 1 to 255",
		},
		{
			name:    "timeout 0",
			modify:  func(o *Options) { o.Timeout = 0 },
			wantErr: "--timeout must be positive",
		},
		{
			name:    "bad url",
			modify:  func(o *Options) { o.URLs = []string{"https://a.test"} },
			wantErr: `--url: "https://a.test": give the host only, without a scheme`,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			opts := testOptions("a.test")
			tc.modify(&opts)
			var stdout bytes.Buffer
			err := run(context.Background(), opts, deps{}, &stdout, &bytes.Buffer{})
			assert.EqualError(t, err, tc.wantErr)
			assert.Empty(t, stdout.String(), "no report")
		})
	}

	opts := testOptions("a.test")
	opts.MaxTTL = 255
	_, err := opts.targets()
	assert.NoError(t, err)
}

// timeline records the order of the hop measurements of addresses, and of
// the QUIC and DPI checks of targets, and whether the DPI checks of two
// targets overlap.
type timeline struct {
	mu        sync.Mutex
	events    []string
	activeDPI map[string]bool
	overlaps  map[[2]string]bool
	firstStep map[string]dpiStep
}

func newTimeline() *timeline {
	return &timeline{
		activeDPI: map[string]bool{},
		overlaps:  map[[2]string]bool{},
		firstStep: map[string]dpiStep{},
	}
}

func (tl *timeline) record(event string) {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	tl.events = append(tl.events, event)
}

func (tl *timeline) dial(inner dialFunc) dialFunc {
	return func(ctx context.Context, ttl int, addr netip.AddrPort) (net.Conn, error) {
		tl.record("hops " + addr.Addr().String())
		return inner(ctx, ttl, addr)
	}
}

func (tl *timeline) quicAttempts(server netip.AddrPort) quicAttemptFunc {
	return func(_ context.Context, sni string) quicAttemptResult {
		tl.record("quic " + server.Addr().String() + " " + sni)
		return quicAttemptResult{outcome: quicReply}
	}
}

func (tl *timeline) attempts(_ netip.AddrPort, host string) attemptFunc {
	return func(ctx context.Context, a attempt) outcome {
		tl.mu.Lock()
		tl.events = append(tl.events, "dpi "+host)
		if _, ok := tl.firstStep[host]; !ok {
			tl.firstStep[host] = a.step
		}
		for other, active := range tl.activeDPI {
			if other != host && active {
				tl.overlaps[[2]string{min(host, other), max(host, other)}] = true
			}
		}
		tl.activeDPI[host] = true
		tl.mu.Unlock()
		// Long enough for the other targets to start.
		time.Sleep(5 * time.Millisecond)
		tl.mu.Lock()
		tl.activeDPI[host] = false
		tl.mu.Unlock()
		return outcome{kind: outPass}
	}
}

// index returns the index of the first event that starts with prefix, or
// of the last one when last is set, or -1.
func (tl *timeline) index(prefix string, last bool) int {
	found := -1
	for i, e := range tl.events {
		if strings.HasPrefix(e, prefix) {
			if !last {
				return i
			}
			found = i
		}
	}
	return found
}

func TestRun_CheckPhases(t *testing.T) {
	tl := newTimeline()
	d := testDeps(hosts(map[string]string{
		"a.test": "203.0.113.1", "a-alias.test": "203.0.113.1", "b.test": "203.0.113.2",
	}), nil, nil)
	d.dialTCP = tl.dial(fakeTCP(3, nil))
	d.dialUDP = tl.dial(refusedUDP)
	d.attempts = tl.attempts
	d.quicAttempts = tl.quicAttempts

	opts := testOptions("a.test", "b.test", "a-alias.test")
	opts.MaxTTL = 4
	var stdout, stderr bytes.Buffer
	require.NoError(t, run(context.Background(), opts, d, &stdout, &stderr))

	const a = "203.0.113.1"
	assert.Less(t, tl.index("hops "+a, true), tl.index("quic "+a, false),
		"the hops of every target at an address come before their checks")
	assert.Less(t, tl.index("quic "+a+" a.test", true), tl.index("dpi a.test", false),
		"the QUIC check of a target comes before its DPI checks")
	assert.Less(t, tl.index("quic "+a+" "+benignSNI, false),
		tl.index("quic "+a+" a.test", false), "the benign Initial goes first")
	assert.Less(
		t,
		tl.index("dpi a.test", true),
		tl.index("quic "+a+" a-alias.test", false),
		"the checks of targets at one address run in --url order",
	)
	assert.Less(
		t,
		tl.index("quic "+a+" a-alias.test", true),
		tl.index("dpi a-alias.test", false),
	)
	assert.False(t, tl.overlaps[[2]string{"a-alias.test", "a.test"}],
		"DPI checks at one address overlap")
	assert.True(
		t,
		tl.overlaps[[2]string{"a.test", "b.test"}] ||
			tl.overlaps[[2]string{"a-alias.test", "b.test"}],
		"DPI checks at different addresses run concurrently",
	)

	assert.Equal(t, stepConnect, tl.firstStep["a.test"], "the DPI checks connect first")
	assert.Equal(
		t,
		stepConnect,
		tl.firstStep["a-alias.test"],
		"the DPI checks connect first",
	)
}

func TestRun_InterruptedDuringDPI(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	d := testDeps(
		hosts(map[string]string{"fast.test": "203.0.113.1", "slow.test": "203.0.113.2"}),
		fakeTCP(1, nil), nil)
	var once sync.Once
	d.attempts = func(server netip.AddrPort, host string) attemptFunc {
		if host == "fast.test" {
			return clearPath(server, host)
		}
		return func(ctx context.Context, a attempt) outcome {
			once.Do(func() { time.AfterFunc(100*time.Millisecond, cancel) })
			<-ctx.Done()
			return outcome{kind: outDrop}
		}
	}

	var stdout, stderr bytes.Buffer
	start := time.Now()
	err := run(
		ctx,
		testOptions("fast.test", "slow.test"),
		d,
		&stdout,
		&stderr,
	)
	assert.Less(t, time.Since(start), 5*time.Second)
	var interrupted *InterruptedError
	require.ErrorAs(t, err, &interrupted)
	assert.Contains(t, stdout.String(), "fast.test")
	assert.NotContains(
		t,
		stdout.String(),
		"slow.test",
		"the unfinished target has no block",
	)
}

func TestRun_InterruptedDuringQUIC(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	d := testDeps(
		hosts(map[string]string{"fast.test": "203.0.113.1", "slow.test": "203.0.113.2"}),
		fakeTCP(1, nil), nil)
	var once sync.Once
	d.quicAttempts = func(server netip.AddrPort) quicAttemptFunc {
		if server.Addr() == netip.MustParseAddr("203.0.113.1") {
			return clearQUIC(server)
		}
		return func(ctx context.Context, sni string) quicAttemptResult {
			once.Do(func() { time.AfterFunc(100*time.Millisecond, cancel) })
			<-ctx.Done()
			return quicAttemptResult{outcome: quicNoReply}
		}
	}
	var dpiSlow atomic.Bool
	d.attempts = func(server netip.AddrPort, host string) attemptFunc {
		if host == "slow.test" {
			dpiSlow.Store(true)
		}
		return clearPath(server, host)
	}

	var stdout, stderr bytes.Buffer
	err := run(ctx, testOptions("fast.test", "slow.test"), d, &stdout, &stderr)
	var interrupted *InterruptedError
	require.ErrorAs(t, err, &interrupted)
	assert.Contains(t, stdout.String(), "fast.test")
	assert.NotContains(
		t,
		stdout.String(),
		"slow.test",
		"the unfinished target has no block",
	)
	assert.False(t, dpiSlow.Load(), "no DPI checks after an interrupted QUIC check")
}

// recordedStatus records what run reports to the status line.
type recordedStatus struct {
	mu      sync.Mutex
	urls    []string
	events  []progressEvent
	stopped int
}

func (r *recordedStatus) start(
	stderr io.Writer,
	urls []string,
) (progressFunc, io.Writer, func()) {
	r.urls = urls
	return func(e progressEvent) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.events = append(r.events, e)
		}, stderr, func() {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.stopped++
		}
}

// index returns the index of the first event of target with phase, or
// -1.
func (r *recordedStatus) index(target int, phase string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, e := range r.events {
		if e.target == target && e.phase == phase {
			return i
		}
	}
	return -1
}

func TestRun_StatusGetsStderr(t *testing.T) {
	d := testDeps(hosts(map[string]string{"a.test": "203.0.113.1"}), fakeTCP(1, nil), nil)
	var given io.Writer
	var lines bytes.Buffer
	d.status = func(stderr io.Writer, urls []string) (progressFunc, io.Writer, func()) {
		given = stderr
		return nil, &lines, func() {}
	}
	var stdout, stderr bytes.Buffer
	opts := testOptions("a.test")
	opts.MaxTTL = 2
	require.NoError(t, run(context.Background(), opts, d, &stdout, &stderr))
	assert.Same(t, &stderr, given, "the status can tell whether stderr is a terminal")
	assert.Contains(
		t,
		lines.String(),
		"probe: dns: ",
		"stderr lines go through the status",
	)
	assert.Empty(t, stderr.String())
}

func TestRun_Progress(t *testing.T) {
	d := testDeps(
		hosts(map[string]string{"a.test": "203.0.113.1"}),
		fakeTCP(2, nil),
		refusedUDP,
	)
	var rec recordedStatus
	d.status = rec.start

	var stdout, stderr bytes.Buffer
	opts := testOptions("a.test", "missing.test")
	opts.MaxTTL = 3
	require.NoError(t, run(context.Background(), opts, d, &stdout, &stderr))

	assert.Equal(t, []string{"a.test", "missing.test"}, rec.urls)
	assert.Positive(t, rec.stopped, "the status line is cleared")
	done := map[int]int{}
	phases := map[int][]string{}
	for _, e := range rec.events {
		if e.done {
			done[e.target]++
		} else {
			phases[e.target] = append(phases[e.target], e.phase)
		}
	}
	assert.Equal(t, map[int]int{0: 1, 1: 1}, done, "every target is done once")
	assert.Equal(
		t,
		[]string{"resolving", "hops", "queued for checks", "quic", "dpi connect"},
		phases[0][:5],
		"the QUIC check comes before the DPI checks",
	)
	assert.Contains(t, phases[0], "dpi block")
	assert.Equal(t, []string{"resolving"}, phases[1], "an unresolved target")
	assert.Equal(t, captureWarning+"\n",
		strings.SplitAfterN(stderr.String(), "\n", 2)[1], "warnings still reach stderr")
}

func TestRun_ResidualFromBlockedTarget(t *testing.T) {
	tcs := []struct {
		name     string
		firstRST bool
		wantNote string
	}{
		{
			name:     "after a blocked target",
			firstRST: true,
			wantNote: "residual block from a.test",
		},
		{
			name:     "after a clear target",
			wantNote: "benign baseline: silent",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			d := testDeps(hosts(map[string]string{
				"a.test": "203.0.113.1", "a-alias.test": "203.0.113.1",
			}), fakeTCP(1, nil), nil)
			var mu sync.Mutex
			secondBenign := 0
			d.attempts = func(_ netip.AddrPort, host string) attemptFunc {
				return func(_ context.Context, a attempt) outcome {
					mu.Lock()
					defer mu.Unlock()
					switch {
					case host == "a.test" && a.step == stepUnsplit && tc.firstRST:
						return outcome{kind: outRST}
					case host == "a.test" && a.step == stepPositionRST:
						return outcome{kind: outRST}
					case host == "a-alias.test" && a.step == stepBenign:
						// The first benign ClientHello of the second
						// target is dropped.
						if secondBenign++; secondBenign == 1 {
							return outcome{kind: outDrop}
						}
					}
					return outcome{kind: outPass}
				}
			}
			opts := testOptions("a.test", "a-alias.test")
			opts.MaxTTL = 2
			var stdout, stderr bytes.Buffer
			require.NoError(t, run(context.Background(), opts, d, &stdout, &stderr))
			out := stdout.String()
			second := out[strings.Index(out, "a-alias.test ("):]
			assert.Contains(t, second, tc.wantNote)
		})
	}
}

// withCapture makes every capture of d open.
func withCapture(t *testing.T, d *deps) {
	d.openCapture = func(captureKind, []netip.Addr) (packetSource, error) {
		return newFakeSource(t), nil
	}
}

func TestRun_FakeAndServer(t *testing.T) {
	d := testDeps(hosts(map[string]string{
		"blocked.test": "203.0.113.1", "clear.test": "203.0.113.2",
	}), fakeTCP(5, nil), nil)
	withCapture(t, &d)
	var opened atomic.Int32
	var servers []netip.Addr
	d.openFakes = func(_ context.Context, s []netip.Addr) (fakeStack, error) {
		opened.Add(1)
		servers = s
		return &scriptedFakes{}, nil
	}
	d.attempts = func(server netip.AddrPort, host string) attemptFunc {
		f := &fakeDPI{
			fakePass:     fooled(true, 9999, 66000, true),
			serverAnswer: breaksBelow(517, 0, outcome{kind: outOther, detail: "closed"}),
		}
		if host == "blocked.test" {
			f.blocked, f.hop = outRST, 3
		}
		return f.attempt
	}

	var stdout, stderr bytes.Buffer
	opts := testOptions("blocked.test", "clear.test")
	opts.MaxTTL = 8
	require.NoError(t, run(context.Background(), opts, d, &stdout, &stderr))
	assert.Equal(t, ""+
		"blocked.test (203.0.113.1)\n"+
		"  https\n"+
		"    status      censored\n"+
		"    hops(tcp)   4 actual / - (not learned)\n"+
		"    dpi\n"+
		"      type      RST\n"+
		"      chunks    reassembled\n"+
		"      disorder  x (DPI reorders segments)\n"+
		"      position  3\n"+
		"      fake\n"+
		"        ttl          ok\n"+
		"        seq_offset   ok up to -8192 (x at -16384)\n"+
		"        ack_offset   ok up to -65536 (x at -131072)\n"+
		"        bad_md5      ok\n"+
		"    server\n"+
		"      bad_sni      answers\n"+
		"      seq_offset   drops at -1024 or below; breaks (closed) at -512\n"+
		"      ack_offset   drops at every offset\n"+
		"      bad_md5      drops\n"+
		"  quic\n"+
		"    status      clear\n"+
		"    hops(udp)   0 actual / - (not learned)\n"+
		"\n"+
		"clear.test (203.0.113.2)\n"+
		"  https\n"+
		"    status      clear\n"+
		"    hops(tcp)   4 actual / - (not learned)\n"+
		"    server\n"+
		"      bad_sni      answers\n"+
		"      seq_offset   drops at -1024 or below; breaks (closed) at -512\n"+
		"      ack_offset   drops at every offset\n"+
		"      bad_md5      drops\n"+
		"  quic\n"+
		"    status      clear\n"+
		"    hops(udp)   0 actual / - (not learned)\n",
		stdout.String())
	assert.NotContains(t, stderr.String(), "warning")
	assert.Equal(t, int32(1), opened.Load(), "the fake stack is opened once")
	assert.ElementsMatch(
		t,
		[]netip.Addr{
			netip.MustParseAddr("203.0.113.1"),
			netip.MustParseAddr("203.0.113.2"),
		},
		servers,
		"for the servers of the targets",
	)
}

func TestRun_FakesUnavailable(t *testing.T) {
	tcs := []struct {
		name   string
		err    error
		reason string
		hint   string
	}{
		{
			name:   "no route",
			err:    errors.New("resolve gateway MAC: timed out"),
			reason: "fake packets unavailable",
		},
		{
			name:   "no capture",
			err:    fmt.Errorf("%w: %w", errFakeCapture, errors.New("permission denied")),
			reason: "needs root",
			hint:   "; run as root",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			d := testDeps(hosts(map[string]string{
				"a.test": "203.0.113.1", "b.test": "203.0.113.2",
			}), fakeTCP(4, nil), nil)
			withCapture(t, &d)
			d.openFakes = func(context.Context, []netip.Addr) (fakeStack, error) {
				return nil, tc.err
			}
			d.attempts = func(netip.AddrPort, string) attemptFunc {
				return (&fakeDPI{blocked: outRST, hop: 2}).attempt
			}
			var stdout, stderr bytes.Buffer
			opts := testOptions("a.test", "b.test")
			opts.MaxTTL = 8
			require.NoError(t, run(context.Background(), opts, d, &stdout, &stderr))
			assert.Equal(t, 1, strings.Count(stderr.String(), "warning"), "one warning")
			assert.Contains(t, stderr.String(),
				"probe: warning: fake packets unavailable ("+tc.err.Error()+"); "+
					"the fake and server checks are skipped"+tc.hint+"\n")
			assert.Equal(t, 2, strings.Count(stdout.String(),
				"      fake      unknown ("+tc.reason+")\n"))
			assert.Equal(t, 2, strings.Count(stdout.String(),
				"    server      unknown ("+tc.reason+")\n"))
		})
	}
}

func TestRun_NoCaptureSkipsFakeStack(t *testing.T) {
	d := testDeps(hosts(map[string]string{"a.test": "203.0.113.1"}), fakeTCP(1, nil), nil)
	d.openFakes = func(context.Context, []netip.Addr) (fakeStack, error) {
		t.Error("the fake stack is opened without the flow capture")
		return nil, errors.New("unexpected")
	}
	var stdout, stderr bytes.Buffer
	opts := testOptions("a.test")
	opts.MaxTTL = 2
	require.NoError(t, run(context.Background(), opts, d, &stdout, &stderr))
	assert.Equal(t, 1, strings.Count(stderr.String(), "warning"),
		"the capture warning covers the fake checks")
	assert.Contains(t, stdout.String(), "    server      unknown (needs root)\n")
}

func TestRun_ResidualFromServerCheck(t *testing.T) {
	tcs := []struct {
		name string
		// residual makes the residual check after the first target's
		// server check fail.
		residual bool
		wantNote string
	}{
		{
			name:     "server check left a residual block",
			residual: true,
			wantNote: "residual block from a.test",
		},
		{name: "none left", wantNote: "benign baseline: silent"},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			d := testDeps(hosts(map[string]string{
				"a.test": "203.0.113.1", "a-alias.test": "203.0.113.1",
			}), fakeTCP(3, nil), nil)
			withCapture(t, &d)
			d.openFakes = func(context.Context, []netip.Addr) (fakeStack, error) {
				return &scriptedFakes{}, nil
			}
			var mu sync.Mutex
			benign := map[string]int{}
			d.attempts = func(_ netip.AddrPort, host string) attemptFunc {
				return func(_ context.Context, a attempt) outcome {
					mu.Lock()
					defer mu.Unlock()
					if a.step != stepBenign {
						return outcome{kind: outPass}
					}
					benign[host]++
					switch {
					case host == "a.test" && benign[host] == 2 && tc.residual:
						return outcome{kind: outDrop}
					case host == "a-alias.test" && benign[host] == 1:
						// The first benign ClientHello of the second
						// target is dropped.
						return outcome{kind: outDrop}
					}
					return outcome{kind: outPass}
				}
			}
			opts := testOptions("a.test", "a-alias.test")
			opts.MaxTTL = 8
			var stdout, stderr bytes.Buffer
			require.NoError(t, run(context.Background(), opts, d, &stdout, &stderr))
			out := stdout.String()
			first := out[:strings.Index(out, "a-alias.test (")]
			second := out[strings.Index(out, "a-alias.test ("):]
			if tc.residual {
				assert.Contains(t, first, "    server      ?\n")
			}
			assert.Contains(t, first, "    status      clear\n")
			assert.Contains(t, second, tc.wantNote)
		})
	}
}

func TestRun_QUICResidual(t *testing.T) {
	tcs := []struct {
		name string
		// clearAfter is the number of benign Initials of the second target
		// that go unanswered; -1 means all.
		clearAfter int
		wantQUIC   string
	}{
		{
			name:       "cleared after waiting",
			clearAfter: 1,
			wantQUIC: "" +
				"    status      clear\n" +
				"    note        waited 0s for residual block from a.test\n",
		},
		{
			name:       "not cleared",
			clearAfter: -1,
			wantQUIC: "" +
				"    status      ?\n" +
				"    note        residual block from a.test (not cleared after 0s)\n",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			d := testDeps(hosts(map[string]string{
				"a.test": "203.0.113.1", "a-alias.test": "203.0.113.1",
			}), fakeTCP(1, nil), nil)
			var mu sync.Mutex
			var sent []string
			blocked := false
			unanswered := 0
			d.quicAttempts = func(netip.AddrPort) quicAttemptFunc {
				return func(_ context.Context, sni string) quicAttemptResult {
					mu.Lock()
					defer mu.Unlock()
					sent = append(sent, sni)
					switch {
					case sni == "a.test":
						// The Initial for a.test is blocked, and leaves a
						// residual block.
						blocked = true
						return quicAttemptResult{outcome: quicNoReply}
					case blocked && (tc.clearAfter < 0 || unanswered < tc.clearAfter):
						unanswered++
						return quicAttemptResult{outcome: quicNoReply}
					}
					return quicAttemptResult{outcome: quicReply}
				}
			}
			var stdout, stderr bytes.Buffer
			opts := testOptions("a.test", "a-alias.test")
			opts.MaxTTL = 2
			require.NoError(t, run(context.Background(), opts, d, &stdout, &stderr))
			out := stdout.String()
			first := out[:strings.Index(out, "a-alias.test (")]
			second := out[strings.Index(out, "a-alias.test ("):]
			assert.Contains(t, first, "  quic\n    status      censored\n")
			assert.Contains(t, second, "  quic\n"+tc.wantQUIC)
			if tc.clearAfter < 0 {
				assert.NotContains(t, sent, "a-alias.test", "the real Initial is not sent")
			}
		})
	}
}
