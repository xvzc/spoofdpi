package probe

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/capture"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/packet"
	"github.com/xvzc/spoofdpi/internal/proto"
)

// fakeTLSServer listens on loopback and serves every connection with
// serve, which reads the whole ClientHello first.
func fakeTLSServer(
	t *testing.T,
	serve func(conn net.Conn, hello *proto.TLSMessage),
) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				hello, err := proto.ReadTLSMessage(conn)
				if err != nil {
					return
				}
				serve(conn, hello)
			}()
		}
	}()
	return netip.MustParseAddrPort(ln.Addr().String())
}

func serverHello(conn net.Conn, _ *proto.TLSMessage) {
	_, _ = conn.Write([]byte{0x16, 3, 3, 0, 90, 0x02, 0, 0, 86})
}

func resetConn(conn net.Conn, _ *proto.TLSMessage) {
	_ = conn.(*net.TCPConn).SetLinger(0)
}

func stayQuiet(conn net.Conn, _ *proto.TLSMessage) {
	_, _ = io.Copy(io.Discard, conn)
}

func attemptProber() *Prober {
	p := testProber(dialer("tcp4"), nil)
	p.sender = newHelloSender()
	return p
}

func TestHelloAttempt(t *testing.T) {
	tcs := []struct {
		name  string
		serve func(net.Conn, *proto.TLSMessage)
		want  outcomeKind
	}{
		{name: "pass", serve: serverHello, want: outPass},
		{name: "rst", serve: resetConn, want: outRST},
		{name: "silent", serve: stayQuiet, want: outDrop},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			server := fakeTLSServer(t, tc.serve)
			attempts := attemptProber().dpiAttempts(server, "www.example.com")
			for _, a := range []attempt{
				{step: stepUnsplit},
				{step: stepChunks, size: 5},
				{step: stepDisorder, size: 5},
				{step: stepBenign},
			} {
				a.wait = 300 * time.Millisecond
				assert.Equal(
					t,
					tc.want,
					attempts(context.Background(), a).kind,
					"step %d",
					a.step,
				)
			}
		})
	}
}

func TestHelloAttempt_SNI(t *testing.T) {
	snis := make(chan string, 2)
	server := fakeTLSServer(t, func(conn net.Conn, hello *proto.TLSMessage) {
		start, end, err := hello.ExtractSNIOffset()
		if err == nil {
			snis <- string(hello.Raw()[start:end])
		}
		serverHello(conn, hello)
	})
	attempts := attemptProber().dpiAttempts(server, "blocked.example")
	attempts(context.Background(), attempt{step: stepUnsplit, wait: time.Second})
	attempts(context.Background(), attempt{step: stepBenign, wait: time.Second})
	assert.Equal(t, "blocked.example", <-snis)
	assert.Equal(t, benignSNI, <-snis)
}

func TestConnectAttempt(t *testing.T) {
	server := fakeTLSServer(t, stayQuiet)
	o := attemptProber().dpiAttempts(server, "a.test")(context.Background(),
		attempt{step: stepConnect})
	assert.Equal(t, outPass, o.kind)
	assert.Positive(t, o.rtt)

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	closed := netip.MustParseAddrPort(ln.Addr().String())
	require.NoError(t, ln.Close())
	o = attemptProber().dpiAttempts(closed, "a.test")(context.Background(),
		attempt{step: stepConnect})
	assert.Equal(t, outcome{kind: outRST, connectFailed: true}, o)
}

func TestHelloAttempt_Interrupted(t *testing.T) {
	server := fakeTLSServer(t, stayQuiet)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	start := time.Now()
	attemptProber().dpiAttempts(server, "a.test")(
		ctx,
		attempt{step: stepUnsplit, wait: time.Minute},
	)
	assert.Less(t, time.Since(start), 5*time.Second)
}

func TestRSTPositionAttempt(t *testing.T) {
	// On loopback the TTL does not matter: the server gets the ClientHello.
	attempts := attemptProber().dpiAttempts(fakeTLSServer(t, resetConn), "a.test")
	o := attempts(
		context.Background(),
		attempt{step: stepPositionRST, ttl: 5, wait: time.Second},
	)
	assert.Equal(t, outRST, o.kind)

	attempts = attemptProber().dpiAttempts(fakeTLSServer(t, stayQuiet), "a.test")
	o = attempts(context.Background(),
		attempt{step: stepPositionRST, ttl: 5, wait: 200 * time.Millisecond})
	assert.Equal(t, outDrop, o.kind)
}

// silentServer answers like a server behind a path where every packet
// gets through, and feeds src the segments a capture would see: the
// ClientHello leaving with helloTTL, the byte with byteTTL, and the
// server's duplicate ACK unless dupAck is false.
func silentServer(
	t *testing.T,
	src *fakeSource,
	helloTTL, byteTTL uint8,
	dupAck bool,
) netip.AddrPort {
	t.Helper()
	return fakeTLSServer(t, func(conn net.Conn, hello *proto.TLSMessage) {
		client := netip.MustParseAddrPort(conn.RemoteAddr().String())
		self := netip.MustParseAddrPort(conn.LocalAddr().String())
		const isn = 1000
		end := uint32(isn + hello.Len())
		src.frames <- segmentFrame(t, segment{
			src: client, dst: self, ttl: helloTTL,
			seq: isn, payload: hello.Len(),
		})
		var b [1]byte
		if _, err := io.ReadFull(conn, b[:]); err != nil {
			return
		}
		src.frames <- segmentFrame(t, segment{
			src: client, dst: self, ttl: byteTTL,
			seq: end, payload: 1,
		})
		if dupAck {
			src.frames <- segmentFrame(t, segment{
				src: self, dst: client, ttl: 64,
				ack: isn, sack: [][2]uint32{{end, end + 1}},
			})
		}
		_, _ = io.Copy(io.Discard, conn)
	})
}

func TestSilentPositionAttempt(t *testing.T) {
	tcs := []struct {
		name              string
		helloTTL, byteTTL uint8
		dupAck            bool
		want              outcome
	}{
		{
			name:     "dup ACK",
			helloTTL: 3,
			byteTTL:  64,
			dupAck:   true,
			want:     outcome{kind: outPass},
		},
		{name: "no dup ACK", helloTTL: 3, byteTTL: 64, want: outcome{kind: outDrop}},
		{
			name:     "hello with wrong TTL",
			helloTTL: 64,
			byteTTL:  64,
			dupAck:   true,
			want:     inconclusive,
		},
		{
			name:     "byte with wrong TTL",
			helloTTL: 3,
			byteTTL:  3,
			dupAck:   true,
			want:     inconclusive,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			src := newFakeSource(t)
			server := silentServer(t, src, tc.helloTTL, tc.byteTTL, tc.dupAck)
			p := attemptProber()
			p.flows = newFlowWatch(src)
			defer p.flows.Close()

			o := p.dpiAttempts(server, "a.test")(context.Background(),
				attempt{step: stepPositionSilent, ttl: 3, wait: 300 * time.Millisecond})
			assert.Equal(t, tc.want, o)
		})
	}
}

func TestSilentPositionAttempt_NothingCaptured(t *testing.T) {
	server := fakeTLSServer(t, stayQuiet)
	p := attemptProber()
	p.flows = newFlowWatch(newFakeSource(t))
	defer p.flows.Close()
	o := p.dpiAttempts(server, "a.test")(context.Background(),
		attempt{step: stepPositionSilent, ttl: 3, wait: time.Second})
	assert.Equal(t, inconclusive, o)
}

func tcpSeg(seq, ack uint32, payload int, ttl uint8) capture.TCPSegment {
	return capture.TCPSegment{Seq: seq, Ack: ack, PayloadLen: payload, TTL: ttl}
}

func TestSegmentChecks(t *testing.T) {
	out := func(seq uint32, n int, ttl uint8) flowSegment {
		return flowSegment{out: true, TCPSegment: tcpSeg(seq, 0, n, ttl)}
	}
	in := func(ack uint32, sack ...[2]uint32) flowSegment {
		s := flowSegment{TCPSegment: tcpSeg(0, ack, 0, 50)}
		s.ACK, s.SACK = true, sack
		return s
	}

	// The ClientHello wraps around the sequence space.
	start := uint32(0xffffff00)
	segs := []flowSegment{out(start, 0x100, 3)}
	_, _, v := helloSent(segs, 0x180, 3)
	assert.Equal(t, undecided, v, "not all of it left yet")
	segs = append(segs, out(0, 0x80, 3))
	s, e, v := helloSent(segs, 0x180, 3)
	assert.Equal(t, matched, v)
	assert.Equal(t, start, s)
	assert.Equal(t, uint32(0x80), e)
	_, _, v = helloSent([]flowSegment{out(start, 0x180, 4)}, 0x180, 3)
	assert.Equal(t, failed, v)

	assert.Equal(t, matched, byteSent([]flowSegment{out(e, 1, restoredTTL)}, e, 3))
	assert.Equal(t, failed, byteSent([]flowSegment{out(e, 1, 3)}, e, 3))
	assert.Equal(
		t,
		failed,
		byteSent([]flowSegment{out(e, 2, restoredTTL)}, e, 3),
		"merged",
	)
	assert.Equal(t, failed, byteSent([]flowSegment{out(start, 0x10, restoredTTL)}, e, 3),
		"a retransmission with the restored TTL")
	assert.Equal(t, undecided, byteSent([]flowSegment{out(start, 0x10, 3)}, e, 3))

	assert.Equal(
		t,
		matched,
		dupAcked([]flowSegment{in(start, [2]uint32{e, e + 1})}, start, e),
	)
	assert.Equal(t, matched, dupAcked([]flowSegment{in(start)}, start, e), "no SACK")
	assert.Equal(
		t,
		undecided,
		dupAcked([]flowSegment{in(start, [2]uint32{5, 6})}, start, e),
	)
	assert.Equal(
		t,
		undecided,
		dupAcked([]flowSegment{in(e + 1)}, start, e),
		"acks it all",
	)
}

// scriptedFakes is a fake stack whose desyncer writes the ClientHello and
// shows the flow watch the fake and the ClientHello leaving, as the
// capture would, on a connection whose next sequence numbers are real.
type scriptedFakes struct {
	flows *flowWatch
	real  packet.SeqAck
	// wrongSeq makes every fake carry other sequence numbers, and
	// wrongFirst only the first one.
	wrongSeq, wrongFirst bool
	sendErr              error

	mu    sync.Mutex
	ttls  []uint8
	tries int
}

func (f *scriptedFakes) desyncer(ttl uint8) (helloSender, *fakeLog) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ttls = append(f.ttls, ttl)
	f.tries++
	log := &fakeLog{}
	return scriptedSender{
		f:     f,
		log:   log,
		wrong: f.wrongSeq || f.wrongFirst && f.tries == 1,
	}, log
}

type scriptedSender struct {
	f     *scriptedFakes
	log   *fakeLog
	wrong bool
}

func (s scriptedSender) Desync(
	_ context.Context,
	conn net.Conn,
	msg *proto.TLSMessage,
	opts *config.HTTPSOptions,
) (int, error) {
	local := conn.LocalAddr().(*net.TCPAddr)
	remote := conn.RemoteAddr().(*net.TCPAddr)
	seg := func(sa packet.SeqAck, payload int) capture.TCPSegment {
		return capture.TCPSegment{
			Src: local.IP, Dst: remote.IP,
			SrcPort: uint16(local.Port), DstPort: uint16(remote.Port),
			Seq: sa.Seq, Ack: sa.Ack, ACK: true, PayloadLen: payload, TTL: 64,
		}
	}
	fake := packet.SeqAck{
		Seq: s.f.real.Seq + uint32(opts.FakeSeqOffset),
		Ack: s.f.real.Ack + uint32(opts.FakeAckOffset),
	}
	if s.wrong {
		fake.Seq += 12345
	}
	if s.f.sendErr != nil {
		s.log.err = s.f.sendErr
	} else {
		s.log.sent = 1
		s.log.first = packet.TCPFake{SeqAck: fake, BadMD5Sig: opts.FakeBadMD5Sig}
		s.f.flows.keep(seg(fake, len(config.FakeClientHello)))
	}
	n, err := conn.Write(msg.Raw())
	s.f.flows.keep(seg(s.f.real, len(msg.Raw())))
	return n, err
}

// echoServerHello answers with a ServerHello that echoes the session ID
// of the ClientHello, as a TLS 1.3 server does.
func echoServerHello(conn net.Conn, hello *proto.TLSMessage) {
	_, _ = conn.Write(serverHelloRecord(sessionID(hello.Raw())))
}

func fakeProber(t *testing.T, fakes *scriptedFakes) *Prober {
	t.Helper()
	p := attemptProber()
	p.flows = newFlowWatch(newFakeSource(t))
	t.Cleanup(p.flows.Close)
	fakes.flows = p.flows
	fakes.real = packet.SeqAck{Seq: 1000, Ack: 70000}
	p.fakes = func() (fakeStack, string) { return fakes, "" }
	return p
}

func TestFakeAttempt(t *testing.T) {
	v := seqVariant(10)
	tcs := []struct {
		name      string
		fakes     *scriptedFakes
		serve     func(net.Conn, *proto.TLSMessage)
		want      outcome
		wantTries int
	}{
		{
			name:      "pass",
			fakes:     &scriptedFakes{},
			serve:     echoServerHello,
			want:      outcome{kind: outPass},
			wantTries: 1,
		},
		{
			name:      "blocked",
			fakes:     &scriptedFakes{},
			serve:     resetConn,
			want:      outcome{kind: outRST},
			wantTries: 1,
		},
		{
			name:  "server answers the fake",
			fakes: &scriptedFakes{},
			serve: func(conn net.Conn, _ *proto.TLSMessage) {
				_, _ = conn.Write(serverHelloRecord(fakeSessionID))
			},
			want: outcome{
				kind:          outOther,
				detail:        "answered fake",
				serverReplied: true,
				answeredFake:  true,
			},
			wantTries: 1,
		},
		{
			name:      "seq learned on the second connection",
			fakes:     &scriptedFakes{wrongFirst: true},
			serve:     echoServerHello,
			want:      outcome{kind: outPass},
			wantTries: 2,
		},
		{
			name:      "seq not learned",
			fakes:     &scriptedFakes{wrongSeq: true},
			serve:     echoServerHello,
			want:      localOutcome("seq not learned"),
			wantTries: fakeTries,
		},
		{
			name:      "fake not sent",
			fakes:     &scriptedFakes{sendErr: errors.New("boom")},
			serve:     echoServerHello,
			want:      localOutcome("fake not sent"),
			wantTries: 1,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			server := fakeTLSServer(t, tc.serve)
			p := fakeProber(t, tc.fakes)
			o := p.dpiAttempts(server, "a.test")(context.Background(),
				attempt{step: stepFake, ttl: 7, variant: v, wait: time.Second})
			assert.Equal(t, tc.want, o)
			assert.Equal(t, tc.wantTries, tc.fakes.tries)
			assert.Equal(t, uint8(7), tc.fakes.ttls[0])
		})
	}
}

func TestFakeAttempt_NotCaptured(t *testing.T) {
	server := fakeTLSServer(t, echoServerHello)
	fakes := &scriptedFakes{}
	p := fakeProber(t, fakes)
	// The ClientHello does not show up in the capture.
	p.flows = newFlowWatch(newFakeSource(t))
	t.Cleanup(p.flows.Close)
	o := p.dpiAttempts(server, "a.test")(context.Background(),
		attempt{step: stepFake, ttl: 7, variant: ttlVariant, wait: time.Second})
	assert.Equal(t, localOutcome("seq not verified"), o)
	assert.Equal(t, fakeTries, fakes.tries)
}

func TestServerFakeAttempt(t *testing.T) {
	snis := make(chan string, 1)
	server := fakeTLSServer(t, func(conn net.Conn, hello *proto.TLSMessage) {
		start, end, err := hello.ExtractSNIOffset()
		if err == nil {
			snis <- string(hello.Raw()[start:end])
		}
		echoServerHello(conn, hello)
	})
	fakes := &scriptedFakes{}
	p := fakeProber(t, fakes)
	o := p.dpiAttempts(server, "blocked.example")(context.Background(), attempt{
		step: stepServerFake, variant: badMD5Variant, wait: time.Second,
		linger: 100 * time.Millisecond,
	})
	assert.Equal(t, outcome{kind: outPass}, o)
	assert.Equal(t, benignSNI, <-snis)
	assert.Equal(t, []uint8{restoredTTL}, fakes.ttls, "the fake reaches the server")
}

func TestServerFakeHostAttempt(t *testing.T) {
	snis := make(chan string, 1)
	server := fakeTLSServer(t, func(conn net.Conn, hello *proto.TLSMessage) {
		start, end, err := hello.ExtractSNIOffset()
		if err == nil {
			snis <- string(hello.Raw()[start:end])
		}
		_, _ = conn.Write(serverHelloRecord(fakeSessionID))
	})
	fakes := &scriptedFakes{}
	p := fakeProber(t, fakes)
	o := p.dpiAttempts(server, "clear.example")(context.Background(), attempt{
		step: stepServerFakeHost, variant: ackVariant(50), wait: time.Second,
		linger: 100 * time.Millisecond,
	})
	assert.True(t, o.answeredFake, "the server answered the fake")
	assert.Equal(t, "clear.example", <-snis)
	assert.Equal(t, []uint8{restoredTTL}, fakes.ttls)
}

func TestFakeAttempt_Unavailable(t *testing.T) {
	server := fakeTLSServer(t, echoServerHello)
	p := attemptProber()
	a := attempt{step: stepFake, ttl: 7, wait: time.Second}
	o := p.dpiAttempts(server, "a.test")(context.Background(), a)
	assert.Equal(t, localOutcome("needs root"), o, "without a fake stack")

	p.fakes = func() (fakeStack, string) { return nil, "fake packets unavailable" }
	o = p.dpiAttempts(server, "a.test")(context.Background(), a)
	assert.Equal(t, localOutcome("fake packets unavailable"), o)

	p.fakes = func() (fakeStack, string) { return &scriptedFakes{}, "" }
	o = p.dpiAttempts(server, "a.test")(context.Background(), a)
	assert.Equal(t, localOutcome("needs root"), o, "without the flow capture")
}

func TestHelloStart(t *testing.T) {
	out := func(seq, ack uint32, payload int) flowSegment {
		return flowSegment{out: true, TCPSegment: tcpSeg(seq, ack, payload, 64)}
	}
	tcs := []struct {
		name  string
		segs  []flowSegment
		fakes []fakePiece
		want  packet.SeqAck
		v     verdict
	}{
		{
			name: "one segment",
			segs: []flowSegment{out(1000, 7, 1500)},
			want: packet.SeqAck{Seq: 1000, Ack: 7},
			v:    matched,
		},
		{
			name: "two segments after a fake at an offset",
			segs: []flowSegment{out(990, 7, 517), out(1000, 7, 1400), out(2400, 7, 100)},
			want: packet.SeqAck{Seq: 1000, Ack: 7},
			v:    matched,
		},
		{
			name: "a fake at the same seq with another ack",
			segs: []flowSegment{out(1000, 9, 517), out(1000, 7, 1400), out(2400, 7, 100)},
			want: packet.SeqAck{Seq: 1000, Ack: 7},
			v:    matched,
		},
		{
			// The fake at -100, minus the ClientHello's length past its
			// first segment, ends 1500 bytes later where that segment
			// does.
			name:  "a fake whose offset ends it where the first segment does",
			segs:  []flowSegment{out(900, 7, 517), out(1000, 7, 1400), out(2400, 7, 100)},
			fakes: []fakePiece{{SeqAck: packet.SeqAck{Seq: 900, Ack: 7}, length: 517}},
			want:  packet.SeqAck{Seq: 1000, Ack: 7},
			v:     matched,
		},
		{
			name:  "a fake the same as the first segment",
			segs:  []flowSegment{out(1000, 7, 1400), out(1000, 7, 1400), out(2400, 7, 100)},
			fakes: []fakePiece{{SeqAck: packet.SeqAck{Seq: 1000, Ack: 7}, length: 1400}},
			want:  packet.SeqAck{Seq: 1000, Ack: 7},
			v:     matched,
		},
		{
			name: "the end not captured yet",
			segs: []flowSegment{out(1000, 7, 1400)},
			v:    undecided,
		},
		{
			name: "incoming data does not count",
			segs: []flowSegment{{TCPSegment: tcpSeg(1000, 7, 1500, 50)}},
			v:    undecided,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got, v := helloStart(tc.segs, 1500, tc.fakes)
			assert.Equal(t, tc.v, v)
			assert.Equal(t, tc.want, got)
		})
	}
}
