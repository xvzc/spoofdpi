package probe

import (
	"context"
	"errors"
	"fmt"
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

var testServer = netip.MustParseAddrPort("203.0.113.10:443")

// fakeConn is a connection that only has a local address.
type fakeConn struct {
	net.Conn
	local *net.TCPAddr
}

func (c *fakeConn) LocalAddr() net.Addr { return c.local }
func (c *fakeConn) Close() error        { return nil }

// localPorts hands out the local ports of fake connections.
var localPorts atomic.Int32

func newFakeConn() *fakeConn {
	port := 40000 + int(localPorts.Add(1))
	return &fakeConn{local: &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: port}}
}

// fakeTCP returns a dialFunc whose connections complete at the default TTL
// unless baselineErr is set, and at TTL minTTL and above. Lower TTLs fail
// with EHOSTUNREACH, as on Linux.
func fakeTCP(minTTL int, baselineErr error) dialFunc {
	return func(ctx context.Context, ttl int, addr netip.AddrPort) (net.Conn, error) {
		if ttl == 0 && baselineErr != nil {
			return nil, baselineErr
		}
		if ttl != 0 && ttl < minTTL {
			return nil, &net.OpError{
				Op:  "dial",
				Net: "tcp4",
				Err: os.NewSyscallError("connect", syscall.EHOSTUNREACH),
			}
		}
		return newFakeConn(), nil
	}
}

func testProber(dialTCP, dialUDP dialFunc) *Prober {
	return &Prober{
		cfg:       Config{MaxTTL: 16, Timeout: time.Second},
		dialTCP:   dialTCP,
		dialUDP:   dialUDP,
		learnWait: 200 * time.Millisecond,
	}
}

func TestMeasureTCP(t *testing.T) {
	tcs := []struct {
		name        string
		dial        dialFunc
		wantTCP     TCPResult
		wantLearned LearnedResult
	}{
		{
			name:        "measured",
			dial:        fakeTCP(9, nil),
			wantTCP:     TCPResult{Status: TCPMeasured, Hops: 8},
			wantLearned: LearnedResult{Status: LearnedSkipped},
		},
		{
			name:        "local link",
			dial:        fakeTCP(1, nil),
			wantTCP:     TCPResult{Status: TCPMeasured, Hops: 0},
			wantLearned: LearnedResult{Status: LearnedSkipped},
		},
		{
			name:        "above the maximum",
			dial:        fakeTCP(17, nil),
			wantTCP:     TCPResult{Status: TCPAboveMax, Hops: 15},
			wantLearned: LearnedResult{Status: LearnedSkipped},
		},
		{
			name: "no handshake",
			dial: fakeTCP(
				1,
				&net.OpError{
					Op:  "dial",
					Err: os.NewSyscallError("connect", syscall.ECONNREFUSED),
				},
			),
			wantTCP: TCPResult{Status: TCPNoHandshake, Reason: "reset"},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			p := testProber(tc.dial, nil)
			gotTCP, gotLearned := p.measureTCP(context.Background(), testServer)
			assert.Equal(t, tc.wantTCP, gotTCP)
			assert.Equal(t, tc.wantLearned, gotLearned)
		})
	}
}

func TestMeasureTCP_BaselineTries(t *testing.T) {
	var calls atomic.Int32
	p := testProber(
		func(ctx context.Context, ttl int, addr netip.AddrPort) (net.Conn, error) {
			if ttl == 0 && calls.Add(1) < hopTries {
				return nil, context.DeadlineExceeded
			}
			return newFakeConn(), nil
		},
		nil,
	)
	got, _ := p.measureTCP(context.Background(), testServer)
	assert.Equal(t, TCPResult{Status: TCPMeasured, Hops: 0}, got)
	assert.Equal(t, int32(hopTries), calls.Load(), "the last baseline attempt completes")

	calls.Store(0)
	p = testProber(
		func(ctx context.Context, ttl int, addr netip.AddrPort) (net.Conn, error) {
			calls.Add(1)
			return nil, context.DeadlineExceeded
		},
		nil,
	)
	got, _ = p.measureTCP(context.Background(), testServer)
	assert.Equal(t, TCPResult{Status: TCPNoHandshake, Reason: "timeout"}, got)
	assert.Equal(t, int32(hopTries), calls.Load(), "no scan without a baseline")
}

func TestMeasureTCP_AttemptTimeout(t *testing.T) {
	p := testProber(
		func(ctx context.Context, ttl int, addr netip.AddrPort) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
		nil,
	)
	p.cfg.Timeout = 50 * time.Millisecond
	start := time.Now()
	got, _ := p.measureTCP(context.Background(), testServer)
	assert.Equal(t, TCPResult{Status: TCPNoHandshake, Reason: "timeout"}, got)
	assert.Less(t, time.Since(start), time.Second)
}

func TestMeasureTCP_Unstable(t *testing.T) {
	reach := fakeTCP(9, nil)
	p := testProber(
		func(ctx context.Context, ttl int, addr netip.AddrPort) (net.Conn, error) {
			if ttl == 12 {
				return nil, context.DeadlineExceeded
			}
			return reach(ctx, ttl, addr)
		},
		nil,
	)
	got, _ := p.measureTCP(context.Background(), testServer)
	assert.Equal(t, TCPResult{Status: TCPMeasured, Hops: 8, Unstable: true}, got)
}

func TestMeasureTCP_LocalError(t *testing.T) {
	emfile := &net.OpError{Op: "dial", Err: os.NewSyscallError("socket", syscall.EMFILE)}

	t.Run("baseline", func(t *testing.T) {
		p := testProber(fakeTCP(1, emfile), nil)
		got, learned := p.measureTCP(context.Background(), testServer)
		assert.Equal(t, TCPResult{
			Status: TCPNoHandshake,
			Reason: "local error: too many open files",
		}, got)
		assert.Equal(t, LearnedResult{}, learned)
	})

	t.Run("scan", func(t *testing.T) {
		reach := fakeTCP(9, nil)
		p := testProber(
			func(ctx context.Context, ttl int, addr netip.AddrPort) (net.Conn, error) {
				if ttl == 9 {
					return nil, emfile
				}
				return reach(ctx, ttl, addr)
			},
			nil,
		)
		got, _ := p.measureTCP(context.Background(), testServer)
		assert.Equal(t, TCPResult{
			Status:     TCPMeasured,
			Hops:       9,
			LocalError: "too many open files",
		}, got, "the TTL that failed locally does not count as a miss silently")
	})
}

func TestTCPFailure(t *testing.T) {
	opErr := func(errno syscall.Errno) error {
		return &net.OpError{
			Op:  "dial",
			Net: "tcp4",
			Err: os.NewSyscallError("connect", errno),
		}
	}
	for err, want := range map[error]string{
		opErr(syscall.ECONNREFUSED):                    "reset",
		opErr(syscall.ECONNRESET):                      "reset",
		opErr(syscall.EHOSTUNREACH):                    "unreachable",
		opErr(syscall.ENETUNREACH):                     "unreachable",
		opErr(syscall.EMFILE):                          "local error: too many open files",
		opErr(syscall.EADDRNOTAVAIL):                   "local error: " + syscall.EADDRNOTAVAIL.Error(),
		context.DeadlineExceeded:                       "timeout",
		fmt.Errorf("dial: %w", os.ErrDeadlineExceeded): "timeout",
		errors.New("boom"):                             "boom",
	} {
		assert.Equal(t, want, tcpFailure(err), err.Error())
	}
}

func TestTCPFailure_ClosedLoopbackPort(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	addr := netip.MustParseAddrPort(ln.Addr().String())
	require.NoError(t, ln.Close())

	_, err = dialer("tcp4")(context.Background(), 0, addr)
	require.Error(t, err)
	assert.Equal(t, "reset", tcpFailure(err))
}

func TestCloseReset(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	conn, err := dialer(
		"tcp4",
	)(
		context.Background(),
		0,
		netip.MustParseAddrPort(ln.Addr().String()),
	)
	require.NoError(t, err)
	server, err := ln.Accept()
	require.NoError(t, err)
	defer func() { _ = server.Close() }()

	closeReset(conn)
	require.NoError(t, server.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, err = server.Read(make([]byte, 1))
	assert.ErrorIs(t, err, syscall.ECONNRESET, "the server gets an RST, not a FIN")
}
