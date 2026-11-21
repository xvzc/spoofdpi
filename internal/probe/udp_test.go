package probe

import (
	"context"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// quicServer starts a loopback UDP server that answers each datagram as
// reply returns, or not at all when it returns nil.
func quicServer(t *testing.T, reply func(req []byte) [][]byte) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			for _, b := range reply(buf[:n]) {
				_, _ = pc.WriteTo(b, from)
			}
		}
	}()
	return netip.MustParseAddrPort(pc.LocalAddr().String())
}

// answerVN answers a probe with a Version Negotiation packet, after a
// datagram that is not one.
func answerVN(req []byte) [][]byte {
	if len(req) != quicRequestSize {
		return nil
	}
	dcid, scid := req[6:14], req[15:23]
	return [][]byte{
		{0x40, 1, 2, 3},
		versionNegotiation(scid, dcid, 1),
	}
}

// closedUDPPort returns a loopback UDP address nothing listens on.
func closedUDPPort(t *testing.T) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	addr := netip.MustParseAddrPort(pc.LocalAddr().String())
	require.NoError(t, pc.Close())
	return addr
}

func udpProber() *Prober {
	p := testProber(nil, dialer("udp4"))
	p.cfg = Config{MaxTTL: 4, Timeout: 300 * time.Millisecond}
	return p
}

func TestMeasureUDP_VersionNegotiation(t *testing.T) {
	addr := quicServer(t, answerVN)
	got, learned := udpProber().measureUDP(context.Background(), addr)
	assert.Equal(t, UDPResult{Status: UDPMeasured, Hops: 0}, got)
	assert.Equal(t, LearnedResult{Status: LearnedSkipped}, learned)
}

func TestMeasureUDP_PortUnreachable(t *testing.T) {
	got, learned := udpProber().measureUDP(context.Background(), closedUDPPort(t))
	assert.Equal(t, UDPResult{Status: UDPMeasured, Hops: 0}, got,
		"a port unreachable comes from the server's host")
	assert.Equal(t, LearnedResult{Status: LearnedNoUDPReply}, learned)
}

func TestMeasureUDP_NoReply(t *testing.T) {
	addr := quicServer(t, func([]byte) [][]byte { return nil })
	p := udpProber()
	p.cfg.Timeout = 100 * time.Millisecond
	got, learned := p.measureUDP(context.Background(), addr)
	assert.Equal(t, UDPResult{Status: UDPNoReply, Reason: "no reply"}, got)
	assert.Equal(t, LearnedResult{}, learned)
}

func TestMeasureUDP_BaselineTries(t *testing.T) {
	var requests atomic.Int32
	addr := quicServer(t, func(req []byte) [][]byte {
		// The first two baseline probes go unanswered.
		if requests.Add(1) <= 2 {
			return nil
		}
		return answerVN(req)
	})
	p := udpProber()
	p.cfg.Timeout = 100 * time.Millisecond
	got, _ := p.measureUDP(context.Background(), addr)
	assert.Equal(t, UDPResult{Status: UDPMeasured, Hops: 0}, got,
		"the third baseline probe reaches the server")
}

// unreachableConn is a connected UDP socket whose reads fail as macOS
// reports an ICMP time exceeded.
type unreachableConn struct{ net.Conn }

func (c unreachableConn) Read([]byte) (int, error) {
	return 0, &net.OpError{
		Op:  "read",
		Err: os.NewSyscallError("recvfrom", syscall.EHOSTUNREACH),
	}
}

func TestMeasureUDP_UnreachableEndsAttempt(t *testing.T) {
	addr := quicServer(t, answerVN)
	p := udpProber()
	p.cfg.Timeout = 5 * time.Second
	p.dialUDP = func(ctx context.Context, ttl int, a netip.AddrPort) (net.Conn, error) {
		conn, err := dialer("udp4")(ctx, ttl, a)
		if err != nil || ttl == 0 || ttl >= 3 {
			return conn, err
		}
		return unreachableConn{conn}, nil
	}

	start := time.Now()
	got, _ := p.measureUDP(context.Background(), addr)
	assert.Equal(t, UDPResult{Status: UDPMeasured, Hops: 2}, got)
	assert.Less(
		t,
		time.Since(start),
		2*time.Second,
		"unreachable attempts do not wait for the timeout",
	)

	assert.Equal(t, udpUnreachable, p.udpAttempt(context.Background(), 1, addr).outcome)
}

func TestMeasureUDP_Unreachable(t *testing.T) {
	addr := quicServer(t, answerVN)
	p := udpProber()
	p.dialUDP = func(ctx context.Context, ttl int, a netip.AddrPort) (net.Conn, error) {
		conn, err := dialer("udp4")(ctx, ttl, a)
		if err != nil {
			return conn, err
		}
		return unreachableConn{conn}, nil
	}
	got, _ := p.measureUDP(context.Background(), addr)
	assert.Equal(t, UDPResult{Status: UDPNoReply, Reason: "unreachable"}, got)
}

func TestMeasureUDP_LocalError(t *testing.T) {
	addr := quicServer(t, answerVN)
	emfile := &net.OpError{Op: "dial", Err: os.NewSyscallError("socket", syscall.EMFILE)}

	t.Run("baseline", func(t *testing.T) {
		p := udpProber()
		p.dialUDP = func(ctx context.Context, ttl int, a netip.AddrPort) (net.Conn, error) {
			return nil, emfile
		}
		got, learned := p.measureUDP(context.Background(), addr)
		assert.Equal(t, UDPResult{
			Status: UDPNoReply,
			Reason: "local error: too many open files",
		}, got)
		assert.Equal(t, LearnedResult{}, learned)
	})

	t.Run("scan", func(t *testing.T) {
		p := udpProber()
		p.dialUDP = func(ctx context.Context, ttl int, a netip.AddrPort) (net.Conn, error) {
			if ttl == 1 {
				return nil, emfile
			}
			return dialer("udp4")(ctx, ttl, a)
		}
		got, _ := p.measureUDP(context.Background(), addr)
		assert.Equal(t, UDPResult{
			Status:     UDPMeasured,
			Hops:       1,
			LocalError: "too many open files",
		}, got)
	})
}

func TestUDPFailure(t *testing.T) {
	opErr := func(errno syscall.Errno) error {
		return &net.OpError{Op: "read", Err: os.NewSyscallError("recvfrom", errno)}
	}
	assert.Equal(t, udpPortUnreachable, udpFailure(opErr(syscall.ECONNREFUSED)).outcome)
	assert.Equal(t, udpUnreachable, udpFailure(opErr(syscall.EHOSTUNREACH)).outcome)
	assert.Equal(t, udpUnreachable, udpFailure(opErr(syscall.ENETUNREACH)).outcome)
	assert.Equal(t, udpNoReply, udpFailure(os.ErrDeadlineExceeded).outcome)
	assert.Equal(t,
		udpAttemptResult{outcome: udpLocalError, localErr: syscall.ENOBUFS},
		udpFailure(opErr(syscall.ENOBUFS)))
	assert.Equal(t, "local error: "+syscall.ENOBUFS.Error(),
		udpFailure(opErr(syscall.ENOBUFS)).reason())
}

func TestMeasureUDP_Learned(t *testing.T) {
	for _, tc := range learnedCases {
		t.Run(tc.name, func(t *testing.T) {
			addr := quicServer(t, answerVN)
			src := newFakeSource(t)
			p := udpProber()
			p.cfg.MaxTTL = 12
			p.udpLearner = newLearner(src, parseUDP, []netip.Addr{addr.Addr()})
			defer p.udpLearner.Close()
			if tc.stopped {
				stopCapture(t, p.udpLearner, src)
			}

			var baselines atomic.Int32
			p.dialUDP = func(ctx context.Context, ttl int, a netip.AddrPort) (net.Conn, error) {
				conn, err := dialer("udp4")(ctx, ttl, a)
				if err != nil {
					return conn, err
				}
				port := uint16(conn.LocalAddr().(*net.UDPAddr).Port)
				baseline := ttl == 0 && baselines.Add(1) == 1
				tc.reply(p.udpLearner, src, ttl, baseline, func(ttlLeft uint8) []byte {
					return udpFrame(t, a, port, ttlLeft)
				})
				return conn, nil
			}

			gotUDP, got := p.measureUDP(context.Background(), addr)
			assert.Equal(t, UDPResult{Status: UDPMeasured, Hops: 0}, gotUDP)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestMeasureUDP_LearnedPortUnreachable(t *testing.T) {
	src := newFakeSource(t)
	p := udpProber()
	addr := closedUDPPort(t)
	p.udpLearner = newLearner(src, parseUDP, []netip.Addr{addr.Addr()})
	defer p.udpLearner.Close()

	_, got := p.measureUDP(context.Background(), addr)
	assert.Equal(t, LearnedResult{Status: LearnedNoUDPReply}, got)
}
