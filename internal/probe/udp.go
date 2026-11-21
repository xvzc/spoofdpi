package probe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"time"
)

// udpOutcome is the outcome of one UDP attempt.
type udpOutcome int

const (
	udpNoReply udpOutcome = iota
	// udpVersionNegotiation: the server answered with a QUIC Version
	// Negotiation packet.
	udpVersionNegotiation
	// udpPortUnreachable: an ICMP port unreachable came back. Only the
	// server's host sends one, so the probe reached it.
	udpPortUnreachable
	// udpUnreachable: an ICMP error other than port unreachable came
	// back, such as time exceeded, which macOS reports this way.
	udpUnreachable
	// udpLocalError: a socket call failed on this host.
	udpLocalError
)

// reached reports whether the attempt reached the server.
func (o udpOutcome) reached() bool {
	return o == udpVersionNegotiation || o == udpPortUnreachable
}

// udpAttemptResult is the outcome of one UDP attempt.
type udpAttemptResult struct {
	outcome udpOutcome
	// localPort is the local port the Version Negotiation reply came to,
	// for udpVersionNegotiation.
	localPort uint16
	// localErr is the error of udpLocalError.
	localErr syscall.Errno
}

// reason says why the attempt did not reach the server.
func (r udpAttemptResult) reason() string {
	switch r.outcome {
	case udpUnreachable:
		return "unreachable"
	case udpLocalError:
		return localErrorReason(r.localErr)
	}
	return "no reply"
}

// measureUDP measures the actual UDP hop count to addr: the smallest TTL
// whose probe the server answers, with a QUIC Version Negotiation packet
// or an ICMP port unreachable. It also measures the hop count spoofdpi
// learns from the server's UDP reply to the probe at the default TTL.
func (p *Prober) measureUDP(
	ctx context.Context,
	addr netip.AddrPort,
) (UDPResult, LearnedResult) {
	mark := 0
	if p.udpLearner != nil {
		mark = p.udpLearner.mark()
	}

	baseline, reason, ok := p.udpBaseline(ctx, addr)
	if !ok {
		return UDPResult{Status: UDPNoReply, Reason: reason}, LearnedResult{}
	}

	learned := LearnedResult{Status: LearnedSkipped}
	var reply observation
	captured := false
	switch {
	case baseline.outcome == udpPortUnreachable:
		// spoofdpi learns from UDP packets only, and an ICMP error is not
		// one.
		learned = LearnedResult{Status: LearnedNoUDPReply}
	case p.udpLearner != nil:
		reply, captured = p.udpLearner.await(ctx, addr, baseline.localPort, p.learnWait)
		if !captured {
			learned = LearnedResult{Status: LearnedNotCaptured}
			if err := p.udpLearner.err(); err != nil {
				learned.Reason = err.Error()
			}
		}
	}

	res := scan(
		ctx,
		p.cfg.MaxTTL,
		hopTries,
		p.stagger,
		func(ctx context.Context, ttl int) (bool, error) {
			r := p.udpAttempt(ctx, ttl, addr)
			if r.outcome == udpLocalError {
				return false, r.localErr
			}
			return r.outcome.reached(), nil
		},
	)

	if captured {
		learned = LearnedResult{
			Status:  Learned,
			Hops:    reply.hops,
			TTLLeft: reply.ttlLeft,
			Seen:    p.udpLearner.hopsSince(mark, addr),
		}
	}

	udp := UDPResult{Status: UDPAboveMax, Hops: p.cfg.MaxTTL - 1}
	if res.minTTL != 0 {
		udp = UDPResult{Status: UDPMeasured, Hops: res.minTTL - 1, Unstable: res.unstable}
	}
	if res.localErr != nil {
		udp.LocalError = res.localErr.Error()
	}
	return udp, learned
}

// udpBaseline probes addr at the default TTL, up to hopTries times. It
// returns the first attempt that reaches the server, or why none did.
func (p *Prober) udpBaseline(
	ctx context.Context,
	addr netip.AddrPort,
) (r udpAttemptResult, reason string, ok bool) {
	reason = "no reply"
	for range hopTries {
		r = p.udpAttempt(ctx, 0, addr)
		if r.outcome.reached() {
			return r, "", true
		}
		// An ICMP error or a local error says more than a missing reply.
		if reason == "no reply" {
			reason = r.reason()
		}
		if ctx.Err() != nil {
			break
		}
	}
	return udpAttemptResult{}, reason, false
}

// udpAttempt sends one QUIC probe with the given TTL from a new socket and
// waits up to the timeout for the Version Negotiation reply to it, or an
// ICMP error.
func (p *Prober) udpAttempt(
	ctx context.Context,
	ttl int,
	addr netip.AddrPort,
) udpAttemptResult {
	ctx, cancel := context.WithTimeout(ctx, p.cfg.Timeout)
	defer cancel()

	conn, err := p.dialUDP(ctx, ttl, addr)
	if err != nil {
		return udpFailure(err)
	}
	defer func() { _ = conn.Close() }()
	// Unblock the read when ctx ends, by its deadline or a cancel.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(time.Now()) })
	defer stop()

	req, dcid, scid := newQUICRequest()
	if _, err := conn.Write(req); err != nil {
		return udpFailure(err)
	}
	buf := make([]byte, 1500)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return udpFailure(err)
		}
		if isVersionNegotiation(buf[:n], dcid, scid) {
			r := udpAttemptResult{outcome: udpVersionNegotiation}
			if a, isUDP := conn.LocalAddr().(*net.UDPAddr); isUDP {
				r.localPort = uint16(a.Port)
			}
			return r
		}
	}
}

// udpFailure classifies the error of a UDP attempt.
func udpFailure(err error) udpAttemptResult {
	if errno, ok := localError(err); ok {
		return udpAttemptResult{outcome: udpLocalError, localErr: errno}
	}
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return udpAttemptResult{outcome: udpPortUnreachable}
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return udpAttemptResult{outcome: udpUnreachable}
	}
	return udpAttemptResult{outcome: udpNoReply}
}
