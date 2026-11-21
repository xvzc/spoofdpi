package probe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGroupByAddr(t *testing.T) {
	a := netip.MustParseAddr("203.0.113.1")
	b := netip.MustParseAddr("203.0.113.2")
	c := netip.MustParseAddr("203.0.113.3")
	assert.Equal(t,
		[][]int{{0, 2, 5}, {1}, {4}},
		groupByAddr([]netip.Addr{a, b, a, {}, c, a}))
	assert.Nil(t, groupByAddr([]netip.Addr{{}, {}}))
}

func TestResolveTarget(t *testing.T) {
	resolveTo := func(addrs ...string) resolveFunc {
		return func(ctx context.Context, host string) ([]netip.Addr, error) {
			var out []netip.Addr
			for _, a := range addrs {
				out = append(out, netip.MustParseAddr(a))
			}
			return out, nil
		}
	}
	failing := func(ctx context.Context, host string) ([]netip.Addr, error) {
		return nil, errors.New("no such host")
	}
	tcs := []struct {
		name     string
		host     string
		resolve  resolveFunc
		wantAddr string
		wantNote string
	}{
		{
			name:     "first IPv4",
			host:     "a.test",
			resolve:  resolveTo("2001:db8::1", "203.0.113.1", "203.0.113.2"),
			wantAddr: "203.0.113.1",
		},
		{
			name:     "mapped IPv4",
			host:     "a.test",
			resolve:  resolveTo("::ffff:203.0.113.1"),
			wantAddr: "203.0.113.1",
		},
		{
			name:     "IPv6 only",
			host:     "a.test",
			resolve:  resolveTo("2001:db8::1"),
			wantNote: "no IPv4 address",
		},
		{
			name:     "no address",
			host:     "a.test",
			resolve:  resolveTo(),
			wantNote: "no IPv4 address",
		},
		{
			name:     "error",
			host:     "a.test",
			resolve:  failing,
			wantNote: "resolve: no such host",
		},
		{
			name:     "IPv4 literal",
			host:     "203.0.113.9",
			resolve:  resolveTo("203.0.113.9"),
			wantAddr: "203.0.113.9",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			addr, note := resolveTarget(
				context.Background(),
				tc.resolve,
				Target{Host: tc.host},
			)
			if tc.wantAddr == "" {
				assert.False(t, addr.IsValid())
			} else {
				assert.Equal(t, netip.MustParseAddr(tc.wantAddr), addr)
			}
			assert.Equal(t, tc.wantNote, note)
		})
	}
}

// refusedUDPConn is a connected UDP socket to a closed port. It has only
// the methods a UDP attempt uses.
type refusedUDPConn struct{ net.Conn }

func (refusedUDPConn) Write(b []byte) (int, error) { return len(b), nil }
func (refusedUDPConn) Close() error                { return nil }

func (refusedUDPConn) Read([]byte) (int, error) {
	return 0, &net.OpError{
		Op:  "read",
		Err: os.NewSyscallError("recvfrom", syscall.ECONNREFUSED),
	}
}

func (refusedUDPConn) SetReadDeadline(time.Time) error { return nil }

func refusedUDP(ctx context.Context, ttl int, addr netip.AddrPort) (net.Conn, error) {
	return refusedUDPConn{}, nil
}

func TestProbe_TCPAndUDPRunConcurrently(t *testing.T) {
	var started sync.WaitGroup
	started.Add(2)
	both := make(chan struct{})
	go func() { started.Wait(); close(both) }()
	var once [2]sync.Once
	waitBoth := func(i int) bool {
		once[i].Do(started.Done)
		select {
		case <-both:
			return true
		case <-time.After(5 * time.Second):
			return false
		}
	}

	tcp := fakeTCP(5, nil)
	p := testProber(
		func(ctx context.Context, ttl int, addr netip.AddrPort) (net.Conn, error) {
			if ttl == 0 && !waitBoth(0) {
				return nil, context.DeadlineExceeded
			}
			return tcp(ctx, ttl, addr)
		},
		func(ctx context.Context, ttl int, addr netip.AddrPort) (net.Conn, error) {
			waitBoth(1)
			return refusedUDP(ctx, ttl, addr)
		},
	)
	got := p.Probe(context.Background(), target(t, "a.test"), testServer.Addr())
	assert.Equal(t, TCPResult{Status: TCPMeasured, Hops: 4}, got.TCP)
	assert.Equal(t, LearnedResult{Status: LearnedSkipped}, got.TCPLearned)
	assert.Equal(t, UDPResult{Status: UDPMeasured, Hops: 0}, got.UDP)
	assert.Equal(t, LearnedResult{Status: LearnedNoUDPReply}, got.UDPLearned)
}

func TestProbe_Ports(t *testing.T) {
	var (
		mu    sync.Mutex
		ports = map[string][]uint16{}
	)
	record := func(proto string, inner dialFunc) dialFunc {
		return func(ctx context.Context, ttl int, addr netip.AddrPort) (net.Conn, error) {
			mu.Lock()
			ports[proto] = append(ports[proto], addr.Port())
			mu.Unlock()
			return inner(ctx, ttl, addr)
		}
	}
	got := testProber(record("tcp", fakeTCP(3, nil)), record("udp", refusedUDP)).Probe(
		context.Background(), target(t, "a.test"), testServer.Addr())
	assert.Equal(t, TCPResult{Status: TCPMeasured, Hops: 2}, got.TCP)
	assert.Equal(t, UDPResult{Status: UDPMeasured, Hops: 0}, got.UDP)
	for _, proto := range []string{"tcp", "udp"} {
		assert.NotEmpty(t, ports[proto], proto)
		for _, port := range ports[proto] {
			assert.Equal(t, uint16(443), port, proto)
		}
	}
}
