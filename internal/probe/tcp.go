package probe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
)

// measureTCP measures the actual TCP hop count to addr, and the hop count
// spoofdpi learns from the SYN/ACK of a connection at the default TTL.
func (p *Prober) measureTCP(
	ctx context.Context,
	addr netip.AddrPort,
) (TCPResult, LearnedResult) {
	mark := 0
	if p.tcpLearner != nil {
		mark = p.tcpLearner.mark()
	}

	localPort, reason, ok := p.tcpBaseline(ctx, addr)
	if !ok {
		return TCPResult{Status: TCPNoHandshake, Reason: reason}, LearnedResult{}
	}

	learned := LearnedResult{Status: LearnedSkipped}
	var synAck observation
	captured := false
	if p.tcpLearner != nil {
		synAck, captured = p.tcpLearner.await(ctx, addr, localPort, p.learnWait)
		if !captured {
			learned = LearnedResult{Status: LearnedNotCaptured}
			if err := p.tcpLearner.err(); err != nil {
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
			conn, err := p.dialTCPAttempt(ctx, ttl, addr)
			if err != nil {
				if errno, isLocal := localError(err); isLocal {
					return false, errno
				}
				return false, nil
			}
			closeReset(conn)
			return true, nil
		},
	)

	if captured {
		learned = LearnedResult{
			Status:  Learned,
			Hops:    synAck.hops,
			TTLLeft: synAck.ttlLeft,
			Seen:    p.tcpLearner.hopsSince(mark, addr),
		}
	}

	tcp := TCPResult{Status: TCPAboveMax, Hops: p.cfg.MaxTTL - 1}
	if res.minTTL != 0 {
		tcp = TCPResult{Status: TCPMeasured, Hops: res.minTTL - 1, Unstable: res.unstable}
	}
	if res.localErr != nil {
		tcp.LocalError = res.localErr.Error()
	}
	return tcp, learned
}

// tcpBaseline connects to addr at the default TTL, up to hopTries times.
// It returns the local port of the first connection that completes, or
// why the last attempt failed.
func (p *Prober) tcpBaseline(
	ctx context.Context,
	addr netip.AddrPort,
) (localPort uint16, reason string, ok bool) {
	for range hopTries {
		conn, err := p.dialTCPAttempt(ctx, 0, addr)
		if err == nil {
			if a, isTCP := conn.LocalAddr().(*net.TCPAddr); isTCP {
				localPort = uint16(a.Port)
			}
			closeReset(conn)
			return localPort, "", true
		}
		reason = tcpFailure(err)
		if ctx.Err() != nil {
			break
		}
	}
	return 0, reason, false
}

// dialTCPAttempt makes one connection attempt, bounded by the timeout.
func (p *Prober) dialTCPAttempt(
	ctx context.Context,
	ttl int,
	addr netip.AddrPort,
) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, p.cfg.Timeout)
	defer cancel()
	return p.dialTCP(ctx, ttl, addr)
}

// closeReset closes conn with an RST, so that the server does not keep
// the connection around.
func closeReset(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	_ = conn.Close()
}

// tcpFailure says why a connection attempt failed.
func tcpFailure(err error) string {
	var netErr net.Error
	if errno, ok := localError(err); ok {
		return localErrorReason(errno)
	}
	switch {
	case errors.Is(err, syscall.ECONNREFUSED), errors.Is(err, syscall.ECONNRESET):
		return "reset"
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return "unreachable"
	case errors.Is(err, context.DeadlineExceeded),
		errors.As(err, &netErr) && netErr.Timeout():
		return "timeout"
	}
	return err.Error()
}
