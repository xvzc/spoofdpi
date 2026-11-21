package probe

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"slices"
	"syscall"
	"time"

	"github.com/xvzc/spoofdpi/internal/proto"
)

// quicTries is the most Initials of the QUIC check sent per server name:
// each unanswered one costs a whole timeout, and three make it unlikely
// that lost packets alone report a site as censored.
const quicTries = 3

// quicOutcome is the outcome of one Initial of the QUIC check. The values
// are in the order of how much they tell, least first.
type quicOutcome int

const (
	// quicNoReply: nothing came back.
	quicNoReply quicOutcome = iota
	// quicUnreachable: an ICMP host or network unreachable came back.
	quicUnreachable
	// quicPortUnreachable: an ICMP port unreachable came back, from the
	// server's host.
	quicPortUnreachable
	// quicLocalError: building or sending the Initial failed on this
	// host.
	quicLocalError
	// quicVersionNegotiation: the server answered with a Version
	// Negotiation packet: it does not speak QUIC v1.
	quicVersionNegotiation
	// quicReply: the server answered with a QUIC v1 Initial, Handshake or
	// Retry packet.
	quicReply
)

// answered reports whether the server answered the Initial.
func (o quicOutcome) answered() bool {
	return o == quicReply || o == quicVersionNegotiation
}

// quicAttemptResult is the outcome of one Initial of the QUIC check.
type quicAttemptResult struct {
	outcome quicOutcome
	// localErr is the socket error of quicLocalError, or 0 when detail
	// says what failed instead.
	localErr syscall.Errno
	detail   string
}

// localErrorReason is the reason of a quicLocalError, such as
// "local error: too many open files".
func (r quicAttemptResult) localErrorReason() string {
	if r.localErr != 0 {
		return localErrorReason(r.localErr)
	}
	return "local error: " + r.detail
}

// quicAttemptFunc sends one client Initial for sni from a socket of its
// own and waits for the answer.
type quicAttemptFunc func(ctx context.Context, sni string) quicAttemptResult

// measureQUIC runs the QUIC check of t at addr, an IPv4 address of t.Host:
// it sends a QUIC v1 Initial for the benign name, then one for t.Host, up
// to quicTries times each, and compares whether the server answers them.
// The benign one goes first, so that a block the real one sets off cannot
// spoil it. prev is the URL of the target at the same address whose QUIC
// check may have left a residual block, if any: the benign Initial is then
// retried until the server answers it, for up to the residual limit.
func (p *Prober) measureQUIC(
	ctx context.Context,
	t Target,
	addr netip.Addr,
	prev string,
	progress targetProgress,
) QUICResult {
	attempts := p.quicAttempts
	if attempts == nil {
		attempts = p.quicAttempt
	}
	attempt := attempts(netip.AddrPortFrom(addr, quicPort))

	progress.phase("quic")
	var notes []string
	var benign quicAttemptResult
	if prev == "" {
		benign = quicTry(ctx, attempt, benignSNI)
	} else {
		var waited time.Duration
		var cleared bool
		benign, waited, cleared = p.awaitQUICResidual(ctx, attempt, progress)
		if ctx.Err() != nil {
			return QUICResult{}
		}
		if !cleared {
			return QUICResult{
				Status: QUICSkipped,
				Notes: []string{fmt.Sprintf(
					"residual block from %s (not cleared after %s)",
					prev,
					seconds(p.residual.limit),
				)},
			}
		}
		if waited > 0 {
			notes = append(notes, fmt.Sprintf(
				"waited %s for residual block from %s", seconds(waited), prev))
			progress.phase("quic")
		}
	}
	if ctx.Err() != nil {
		return QUICResult{}
	}
	site := quicTry(ctx, attempt, t.Host)
	if ctx.Err() != nil {
		return QUICResult{}
	}
	res := judgeQUIC(benign, site)
	res.Notes = notes
	return res
}

// quicTry sends the Initial for sni up to quicTries times, until the
// server answers it or a local error stops it, and returns the outcome
// that tells the most.
func quicTry(
	ctx context.Context,
	attempt quicAttemptFunc,
	sni string,
) quicAttemptResult {
	var best quicAttemptResult
	for i := range quicTries {
		r := attempt(ctx, sni)
		if i == 0 || r.outcome > best.outcome {
			best = r
		}
		if r.outcome >= quicLocalError || ctx.Err() != nil {
			break
		}
	}
	return best
}

// awaitQUICResidual sends the benign Initial until the server answers it,
// every residual.recheck for up to residual.limit, and returns that
// outcome. It returns how long it waited when the first Initial was not
// answered, and whether one was. A local error ends the wait with that
// outcome, as it says nothing about a block.
func (p *Prober) awaitQUICResidual(
	ctx context.Context,
	attempt quicAttemptFunc,
	progress targetProgress,
) (r quicAttemptResult, waited time.Duration, cleared bool) {
	start := time.Now()
	for {
		r = attempt(ctx, benignSNI)
		if ctx.Err() != nil {
			return r, 0, false
		}
		if r.outcome.answered() || r.outcome == quicLocalError {
			if waited = time.Since(start); waited < p.residual.recheck {
				waited = 0
			}
			return r, waited, true
		}
		if time.Since(start) >= p.residual.limit {
			return r, 0, false
		}
		progress.wait("waiting for residual block", start, p.residual.limit)
		timer := time.NewTimer(p.residual.recheck)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return r, 0, false
		}
	}
}

// judgeQUIC returns the verdict of the QUIC check from the outcomes of
// the Initials for the benign name and for the target's host, site. A
// site Initial that is not answered, silently or with any ICMP error, is
// censored only when the benign one is answered.
func judgeQUIC(benign, site quicAttemptResult) QUICResult {
	unknown := func(reason string) QUICResult {
		return QUICResult{Status: QUICUnknown, Reason: reason}
	}
	switch {
	case site.outcome == quicReply:
		return QUICResult{Status: QUICClear}
	case site.outcome == quicVersionNegotiation:
		return unknown("no QUIC v1")
	case site.outcome == quicLocalError:
		return unknown(site.localErrorReason())
	case benign.outcome.answered():
		return QUICResult{Status: QUICCensored}
	case benign.outcome == quicLocalError:
		return unknown(benign.localErrorReason())
	case benign.outcome == quicPortUnreachable:
		return unknown("no QUIC")
	case benign.outcome == quicUnreachable && site.outcome == quicUnreachable:
		return QUICResult{Status: QUICUnreachable}
	}
	return unknown("no reply")
}

// quicAttempt returns the attempt of the QUIC check that sends its
// Initials to server at the default TTL.
func (p *Prober) quicAttempt(server netip.AddrPort) quicAttemptFunc {
	return func(ctx context.Context, sni string) quicAttemptResult {
		pkt, dcid, scid, err := newQUICInitial(sni)
		if err != nil {
			return quicAttemptResult{outcome: quicLocalError, detail: err.Error()}
		}

		ctx, cancel := context.WithTimeout(ctx, p.cfg.Timeout)
		defer cancel()
		conn, err := p.dialUDP(ctx, 0, server)
		if err != nil {
			return quicFailure(err)
		}
		defer func() { _ = conn.Close() }()
		// Unblock the read when ctx ends, by its deadline or a cancel.
		stop := context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(time.Now()) })
		defer stop()

		if _, err := conn.Write(pkt); err != nil {
			return quicFailure(err)
		}
		buf := make([]byte, 2048)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return quicFailure(err)
			}
			if o, ok := quicAnswer(buf[:n], dcid, scid); ok {
				return quicAttemptResult{outcome: o}
			}
		}
	}
}

// quicAnswer returns the outcome a datagram b tells for an Initial with
// the connection IDs dcid and scid, and false when it does not answer it:
// a QUIC v1 Initial, Handshake or Retry packet to scid, or a Version
// Negotiation packet that echoes both IDs. A Version Negotiation packet
// that lists version 1, the version of the Initial, is ignored, as RFC
// 9000, section 6.2, requires: it cannot answer it.
func quicAnswer(b, dcid, scid []byte) (quicOutcome, bool) {
	h, err := proto.ParseQUICLongHeader(b)
	if err != nil {
		return 0, false
	}
	switch {
	case h.Type == proto.QUICVersionNegotiation:
		if bytes.Equal(h.DCID, scid) && bytes.Equal(h.SCID, dcid) &&
			!slices.Contains(h.SupportedVersions, proto.QUICVersion1) {
			return quicVersionNegotiation, true
		}
	case h.Version == proto.QUICVersion1 && bytes.Equal(h.DCID, scid):
		switch h.Type {
		case proto.QUICInitial, proto.QUICHandshake, proto.QUICRetry:
			return quicReply, true
		}
	}
	return 0, false
}

// quicFailure classifies the error of an attempt of the QUIC check, as
// udpFailure does for the UDP hop measurement.
func quicFailure(err error) quicAttemptResult {
	r := udpFailure(err)
	switch r.outcome {
	case udpLocalError:
		return quicAttemptResult{outcome: quicLocalError, localErr: r.localErr}
	case udpPortUnreachable:
		return quicAttemptResult{outcome: quicPortUnreachable}
	case udpUnreachable:
		return quicAttemptResult{outcome: quicUnreachable}
	}
	return quicAttemptResult{outcome: quicNoReply}
}
