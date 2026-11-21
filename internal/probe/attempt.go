package probe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/packet"
)

const (
	// ttlConfirmWait bounds the wait for a packet of the silent position
	// check to be captured leaving.
	ttlConfirmWait = 200 * time.Millisecond
	// restoredTTL is the TTL a packet that must reach the server leaves
	// with, as in spoofdpi's disorder.
	restoredTTL = 64
	// fakeTries is the most connections an attempt with a fake makes, when
	// the fake's sequence numbers turn out not to be the connection's.
	fakeTries = 3
)

// inconclusive is the outcome of a silent position try whose packets did
// not leave as they should.
var inconclusive = localOutcome("could not control TTL")

// dpiAttempts returns the attempts of the DPI checks of host at server.
func (p *Prober) dpiAttempts(server netip.AddrPort, host string) attemptFunc {
	return func(ctx context.Context, a attempt) outcome {
		switch a.step {
		case stepConnect:
			return p.connectAttempt(ctx, server)
		case stepPositionRST:
			return p.rstPositionAttempt(ctx, server, host, a)
		case stepPositionSilent:
			return p.silentPositionAttempt(ctx, server, host, a)
		case stepFake:
			return p.fakeAttempt(ctx, server, host, uint8(a.ttl), a)
		case stepServerFake:
			return p.fakeAttempt(ctx, server, benignSNI, restoredTTL, a)
		case stepServerFakeHost:
			return p.fakeAttempt(ctx, server, host, restoredTTL, a)
		}
		sni, opts := host, unsplitOpts()
		switch a.step {
		case stepBenign:
			sni = benignSNI
		case stepChunks:
			opts = chunkOpts(a.size)
		case stepDisorder:
			opts = disorderOpts(a.size)
		}
		return p.helloAttempt(ctx, server, sni, opts, a.wait)
	}
}

// connectAttempt connects to server at the default TTL. Its outcome
// passes when the connection completes, with the time it took.
func (p *Prober) connectAttempt(ctx context.Context, server netip.AddrPort) outcome {
	start := time.Now()
	conn, err := p.dialTCPAttempt(ctx, 0, server)
	if err != nil {
		return dialOutcome(err)
	}
	rtt := time.Since(start)
	closeReset(conn)
	return outcome{kind: outPass, rtt: rtt}
}

// dialForHello connects to server at the default TTL, with a deadline wait
// from now that ctx ending moves to the past. closeConn closes the
// connection with an RST.
func (p *Prober) dialForHello(
	ctx context.Context,
	server netip.AddrPort,
	wait time.Duration,
) (conn net.Conn, closeConn func(), err error) {
	conn, err = p.dialTCPAttempt(ctx, 0, server)
	if err != nil {
		return nil, nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(wait))
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	return conn, func() {
		stop()
		closeReset(conn)
	}, nil
}

// helloAttempt sends a ClientHello for sni to server with opts, and reads
// the answer.
func (p *Prober) helloAttempt(
	ctx context.Context,
	server netip.AddrPort,
	sni string,
	opts *config.HTTPSOptions,
	wait time.Duration,
) outcome {
	msg, err := buildClientHello(sni)
	if err != nil {
		return localOutcome(err.Error())
	}
	conn, closeConn, err := p.dialForHello(ctx, server, wait)
	if err != nil {
		return dialOutcome(err)
	}
	defer closeConn()
	if err := sendHello(ctx, p.sender, conn, msg, opts); err != nil {
		if errors.Is(err, errCannotSetTTL) {
			return localOutcome(err.Error())
		}
		return errOutcome(err)
	}
	return readOutcome(conn)
}

// rstPositionAttempt sends the ClientHello for host with TTL a.ttl, and
// reads the answer. The connection is reset with the same TTL, so that the
// RST does not reach the DPI either.
func (p *Prober) rstPositionAttempt(
	ctx context.Context,
	server netip.AddrPort,
	host string,
	a attempt,
) outcome {
	msg, err := buildClientHello(host)
	if err != nil {
		return localOutcome(err.Error())
	}
	conn, closeConn, err := p.dialForHello(ctx, server, a.wait)
	if err != nil {
		return dialOutcome(err)
	}
	defer closeConn()
	if err := netutil.SetTTL(conn, true, uint8(a.ttl)); err != nil {
		return localOutcome(errCannotSetTTL.Error())
	}
	if _, err := conn.Write(msg.Raw()); err != nil {
		return errOutcome(err)
	}
	return readOutcome(conn)
}

// silentPositionAttempt sends the ClientHello for host with TTL a.ttl,
// then one byte past it with restoredTTL, which reaches the server unless
// the DPI drops the connection. Its outcome passes when the server's
// duplicate ACK of the byte is captured, and drops when none is within
// a.wait. Each packet is confirmed in the capture to have left with its
// TTL; the outcome is inconclusive otherwise.
func (p *Prober) silentPositionAttempt(
	ctx context.Context,
	server netip.AddrPort,
	host string,
	a attempt,
) outcome {
	msg, err := buildClientHello(host)
	if err != nil {
		return localOutcome(err.Error())
	}
	hello := msg.Raw()
	conn, closeConn, err := p.dialForHello(ctx, server, p.cfg.Timeout)
	if err != nil {
		return dialOutcome(err)
	}
	// The RST of the close leaves with TTL a.ttl too.
	defer closeConn()

	local, _ := conn.LocalAddr().(*net.TCPAddr)
	if local == nil {
		return inconclusive
	}
	flow := flowKey{server: server, localPort: uint16(local.Port)}
	untrack := p.flows.track(flow)
	defer untrack()

	ttl := uint8(a.ttl)
	if err := netutil.SetTTL(conn, true, ttl); err != nil {
		return inconclusive
	}
	if _, err := conn.Write(hello); err != nil {
		return errOutcome(err)
	}
	var helloStart, helloEnd uint32
	sent := p.flows.await(ctx, flow, ttlConfirmWait, func(segs []flowSegment) verdict {
		var v verdict
		helloStart, helloEnd, v = helloSent(segs, len(hello), ttl)
		return v
	})
	if sent != matched {
		return inconclusive
	}

	// The byte must leave on its own: the ClientHello has left, so it is
	// not appended to it.
	if err := netutil.SetTTL(conn, true, restoredTTL); err != nil {
		return inconclusive
	}
	if _, err := conn.Write([]byte{0}); err != nil {
		return errOutcome(err)
	}
	sent = p.flows.await(ctx, flow, ttlConfirmWait, func(segs []flowSegment) verdict {
		return byteSent(segs, helloEnd, ttl)
	})
	// Retransmissions of the ClientHello leave with TTL a.ttl again.
	if err := netutil.SetTTL(conn, true, ttl); err != nil || sent != matched {
		return inconclusive
	}

	acked := p.flows.await(ctx, flow, a.wait, func(segs []flowSegment) verdict {
		return dupAcked(segs, helloStart, helloEnd)
	})
	if acked == matched {
		return outcome{kind: outPass}
	}
	return outcome{kind: outDrop}
}

// seqBefore reports whether sequence number a comes before b.
func seqBefore(a, b uint32) bool { return int32(a-b) < 0 }

// helloSent checks that the size bytes of the ClientHello left with TTL
// ttl, and returns the sequence numbers of its first byte and of the byte
// past it.
func helloSent(segs []flowSegment, size int, ttl uint8) (start, end uint32, v verdict) {
	found := false
	for _, s := range segs {
		if !s.out || s.PayloadLen == 0 {
			continue
		}
		if s.TTL != ttl {
			return 0, 0, failed
		}
		if !found || seqBefore(s.Seq, start) {
			start, found = s.Seq, true
		}
	}
	if !found {
		return 0, 0, undecided
	}
	end = start + uint32(size)
	for _, s := range segs {
		if s.out && s.Seq+uint32(s.PayloadLen) == end {
			return start, end, matched
		}
	}
	return start, end, undecided
}

// byteSent checks that the byte at seq helloEnd left on its own with
// restoredTTL, and that no part of the ClientHello left with a TTL other
// than ttl meanwhile.
func byteSent(segs []flowSegment, helloEnd uint32, ttl uint8) verdict {
	for _, s := range segs {
		if !s.out || s.PayloadLen == 0 {
			continue
		}
		switch {
		case s.Seq == helloEnd:
			if s.PayloadLen == 1 && s.TTL == restoredTTL {
				return matched
			}
			return failed
		case seqBefore(s.Seq, helloEnd) && s.TTL != ttl:
			return failed
		}
	}
	return undecided
}

// dupAcked checks for the server's duplicate ACK of the byte past the
// ClientHello: one that acknowledges only up to the ClientHello, with no
// SACK or a SACK of the byte.
func dupAcked(segs []flowSegment, helloStart, helloEnd uint32) verdict {
	for _, s := range segs {
		if s.out || !s.ACK || s.SYN || s.RST || s.PayloadLen > 0 || s.Ack != helloStart {
			continue
		}
		if len(s.SACK) == 0 {
			return matched
		}
		for _, b := range s.SACK {
			if b[0] == helloEnd {
				return matched
			}
		}
	}
	return undecided
}

// fakeSessionID is the session ID of the fake ClientHello.
var fakeSessionID = sessionID([]byte(config.FakeClientHello))

// fakeAttempt sends a fake ClientHello crafted as a.variant with TTL ttl,
// then a ClientHello for sni in one write, as spoofdpi's desyncer does, and
// reads the answer. The fake must carry the connection's sequence numbers
// plus the variant's offsets, as the capture shows them; otherwise the
// attempt is made again on a new connection, up to fakeTries times.
func (p *Prober) fakeAttempt(
	ctx context.Context,
	server netip.AddrPort,
	sni string,
	ttl uint8,
	a attempt,
) outcome {
	stack, reason := p.fakeStack()
	if stack == nil {
		return localOutcome(reason)
	}
	if p.flows == nil {
		return localOutcome("needs root")
	}
	var o outcome
	for range fakeTries {
		var again bool
		o, again = p.fakeTry(ctx, stack, server, sni, ttl, a)
		if !again || ctx.Err() != nil {
			break
		}
	}
	return o
}

// fakeTry makes one try of fakeAttempt. again is set when the fake's
// sequence numbers could not be confirmed.
func (p *Prober) fakeTry(
	ctx context.Context,
	stack fakeStack,
	server netip.AddrPort,
	sni string,
	ttl uint8,
	a attempt,
) (o outcome, again bool) {
	msg, err := buildClientHello(sni)
	if err != nil {
		return localOutcome(err.Error()), false
	}
	// No later than the deadline dialForHello sets.
	deadline := time.Now().Add(a.wait)
	conn, closeConn, err := p.dialForHello(ctx, server, a.wait)
	if err != nil {
		return dialOutcome(err), false
	}
	defer closeConn()

	local, _ := conn.LocalAddr().(*net.TCPAddr)
	if local == nil {
		return localOutcome("seq not verified"), false
	}
	flow := flowKey{server: server, localPort: uint16(local.Port)}
	untrack := p.flows.track(flow)
	defer untrack()

	sender, log := stack.desyncer(ttl)
	// The stack sends the fakes with ttl, whatever the hop-count options.
	if _, err := sender.Desync(
		ctx, conn, msg, fakeOpts(a.variant), &config.ConnOptions{},
	); err != nil {
		return errOutcome(err), false
	}
	// The desyncer sends the real ClientHello even when the fake fails.
	if log.sent == 0 || log.err != nil {
		return localOutcome("fake not sent"), false
	}
	var real packet.SeqAck
	sent := p.flows.await(ctx, flow, ttlConfirmWait, func(segs []flowSegment) verdict {
		var v verdict
		real, v = helloStart(segs, len(msg.Raw()), log.pieces)
		return v
	})
	switch {
	case sent != matched:
		return localOutcome("seq not verified"), true
	case log.first.SeqAck != fakeSeqAck(real, a.variant):
		// The desyncer falls back to random sequence numbers when it does
		// not learn them, and the sniffer may hand it those of an earlier
		// connection from the same port.
		return localOutcome("seq not learned"), true
	}
	return readHello(ctx, conn, &helloCheck{
		real:     sessionID(msg.Raw()),
		fake:     fakeSessionID,
		linger:   a.linger,
		deadline: deadline,
	}), false
}

// fakeSeqAck returns the sequence numbers of a fake crafted as v on a
// connection whose next ones are real, as spoofdpi's desyncer computes
// them.
func fakeSeqAck(real packet.SeqAck, v fakeVariant) packet.SeqAck {
	return packet.SeqAck{
		Seq: real.Seq + uint32(v.seqOffset),
		Ack: real.Ack + uint32(v.ackOffset),
	}
}

// helloStart returns the sequence numbers of the first segment of the
// size bytes of the ClientHello this host sent: those of the segments
// from the one starting it to the one ending it. A segment that is one of
// fakes, the fake packets sent before it, starts the ClientHello only when
// no other segment does: a fake whose seq offset is minus the length of
// the ClientHello past its first segment ends size bytes later just where
// that segment does, and a fake with the connection's own sequence numbers
// and the length of the first segment cannot be told from it.
func helloStart(
	segs []flowSegment,
	size int,
	fakes []fakePiece,
) (packet.SeqAck, verdict) {
	isFake := func(s flowSegment) bool {
		for _, f := range fakes {
			if s.Seq == f.Seq && s.Ack == f.Ack && s.PayloadLen == f.length {
				return true
			}
		}
		return false
	}
	for _, fakeStarts := range []bool{false, true} {
		for _, start := range segs {
			if !start.out || start.PayloadLen == 0 || isFake(start) != fakeStarts {
				continue
			}
			end := start.Seq + uint32(size)
			for _, last := range segs {
				if last.out && last.PayloadLen > 0 && last.Seq+uint32(last.PayloadLen) == end {
					// The last segment is the real one even when the fake
					// starts at the same sequence number.
					return packet.SeqAck{Seq: start.Seq, Ack: last.Ack}, matched
				}
			}
		}
	}
	return packet.SeqAck{}, undecided
}
