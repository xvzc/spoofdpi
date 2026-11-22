package tun

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/desync"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/packet"
	"github.com/xvzc/spoofdpi/internal/proto"
	"github.com/xvzc/spoofdpi/internal/rule"
)

// clientHelloSNI returns the server name in config.FakeClientHello.
func clientHelloSNI(t *testing.T) string {
	t.Helper()
	msg := proto.NewFakeTLSMessage([]byte(config.FakeClientHello))
	start, end, err := msg.ExtractSNIOffset()
	require.NoError(t, err)
	return string(msg.Raw()[start:end])
}

func TestTCPHandler_Handle_Block(t *testing.T) {
	const dstCIDR = "203.0.113.0/24"
	sni := clientHelloSNI(t)

	clientHello := []byte(config.FakeClientHello)
	plain := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

	addrRule := func(block bool) *config.Rule {
		return &config.Rule{
			Name:     "addr",
			Priority: 10,
			Block:    block,
			Match:    &config.MatchAttrs{CIDRs: []string{dstCIDR}},
		}
	}
	domainRule := func(domain string, priority uint16, block bool) *config.Rule {
		return &config.Rule{
			Name:     "domain",
			Priority: priority,
			Block:    block,
			Match:    &config.MatchAttrs{Domains: []string{domain}},
		}
	}

	tcs := []struct {
		name      string
		rules     []*config.Rule
		firstData []byte
		wantDials int32
	}{
		{"address block, plain tcp", []*config.Rule{addrRule(true)}, plain, 0},
		{
			"address block, tls without a domain match",
			[]*config.Rule{addrRule(true), domainRule("other.test", 20, false)},
			clientHello,
			0,
		},
		{"domain block by sni", []*config.Rule{domainRule(sni, 5, true)}, clientHello, 0},
		{
			"higher-priority sni domain block overrides an address allow",
			[]*config.Rule{addrRule(false), domainRule(sni, 20, true)},
			clientHello,
			0,
		},
		{
			"lower-priority sni domain block loses to an address allow",
			[]*config.Rule{addrRule(false), domainRule(sni, 5, true)},
			clientHello,
			1,
		},
		{
			"higher-priority sni domain allow overrides an address block",
			[]*config.Rule{addrRule(true), domainRule(sni, 20, false)},
			clientHello,
			1,
		},
		{
			"lower-priority sni domain allow loses to an address block",
			[]*config.Rule{addrRule(true), domainRule(sni, 5, false)},
			clientHello,
			0,
		},
		{
			"address block wins a priority tie with an sni domain allow",
			[]*config.Rule{addrRule(true), domainRule(sni, 10, false)},
			clientHello,
			0,
		},
		{
			"address allow wins a priority tie with an sni domain block",
			[]*config.Rule{addrRule(false), domainRule(sni, 10, true)},
			clientHello,
			1,
		},
		{"allowed plain tcp is dialed", []*config.Rule{addrRule(false)}, plain, 1},
		{"allowed tls is dialed", []*config.Rule{addrRule(false)}, clientHello, 1},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			rs := rule.NewRuleSet()
			for _, r := range tc.rules {
				require.NoError(t, rs.Add(r))
			}

			h := NewTCPHandler(
				zerolog.Nop(),
				desync.NewTLSDesyncer(zerolog.Nop(), nil, nil, nil, nil),
				rs,
				&config.RuntimeConfig{},
			)

			lConn, peer := net.Pipe()
			defer func() { _ = peer.Close() }()

			sysNet := &dialCountingSysNet{}
			dst := &netutil.Destination{
				Addrs: []net.IP{net.ParseIP("203.0.113.7")},
				Port:  443,
			}

			go func() { _, _ = peer.Write(tc.firstData) }()

			done := make(chan struct{})
			go func() {
				h.Handle(context.Background(), lConn, dst, sysNet)
				close(done)
			}()

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("Handle did not return")
			}

			assert.Equal(t, tc.wantDials, sysNet.dials.Load())

			// The client connection is closed.
			_, err := peer.Read(make([]byte, 1))
			assert.ErrorIs(t, err, io.EOF)
		})
	}
}

// hopRegistrar records the addresses registered for hop-count learning.
type hopRegistrar struct {
	packet.HopReader
	mu         sync.Mutex
	registered [][]net.IP
}

func (r *hopRegistrar) Register(_ packet.Proto, addrs []net.IP) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.registered = append(r.registered, addrs)
}

func (r *hopRegistrar) registrations() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.registered)
}

// deadlineRecordingSysNet records the deadline of the dialer of the first
// dial, which DialFastest sets from the TCP timeout of the selected config,
// and fails the dial.
type deadlineRecordingSysNet struct {
	TUNSystemNetwork
	dials    atomic.Int32
	deadline atomic.Pointer[time.Time]
}

func (s *deadlineRecordingSysNet) BindDialer(d *net.Dialer, _ string, _ net.IP) error {
	s.dials.Add(1)
	deadline := d.Deadline
	s.deadline.CompareAndSwap(nil, &deadline)
	return errors.New("dial disabled in test")
}

// Each selectable config has its own TCP timeout, so the timeout the dial
// carries identifies the config the handler applied. The two timeouts are
// far apart, so a few seconds of test latency cannot confuse them.
const (
	addrRuleTCPTimeout   = 100 * time.Second
	domainRuleTCPTimeout = 200 * time.Second
	timeoutTolerance     = 30 * time.Second
)

func TestTCPHandler_Handle_AppliedConfig(t *testing.T) {
	const dstIP = "203.0.113.7"
	sni := clientHelloSNI(t)
	clientHello := []byte(config.FakeClientHello)

	// An IP literal of the same length as the SNI, so that it can replace it
	// in place.
	const ipLiteral = "203.113.113.177"
	require.Len(t, ipLiteral, len(sni))
	ipLiteralHello := bytes.Replace(clientHello, []byte(sni), []byte(ipLiteral), 1)
	require.NotEqual(t, clientHello, ipLiteralHello)

	plain := []byte("GET / HTTP/1.1\r\nHost: " + sni + "\r\n\r\n")

	addrRule := &config.Rule{
		Name:     "addr",
		Priority: 10,
		Match:    &config.MatchAttrs{CIDRs: []string{"203.0.113.0/24"}},
	}
	addrRule.Config.Conn.TCPTimeout = addrRuleTCPTimeout
	addrRule.Config.HTTPS.FakePreflight = 1

	domainRule := func(domain string, priority uint16, block bool) *config.Rule {
		r := &config.Rule{
			Name:     "domain",
			Priority: priority,
			Block:    block,
			Match:    &config.MatchAttrs{Domains: []string{domain}},
		}
		r.Config.Conn.TCPTimeout = domainRuleTCPTimeout
		return r
	}

	tcs := []struct {
		name      string
		rules     []*config.Rule
		firstData []byte
		// wantTimeout is the TCP timeout the dial must carry, 0 for the
		// base config, which has none.
		wantTimeout time.Duration
		wantHopReg  int
		wantDials   int32
	}{
		{
			"tls: a domain rule matching the sni applies",
			[]*config.Rule{domainRule(sni, 10, false)},
			clientHello, domainRuleTCPTimeout, 0, 1,
		},
		{
			"tls: a domain rule matching the sni applies over a lower address rule",
			[]*config.Rule{addrRule, domainRule(sni, 20, false)},
			clientHello, domainRuleTCPTimeout, 0, 1,
		},
		{
			"tls: a domain rule not matching the sni does not apply",
			[]*config.Rule{domainRule("other.test", 20, false)},
			clientHello, 0, 0, 1,
		},
		{
			"tls: an address rule beats an equal-priority domain rule",
			[]*config.Rule{addrRule, domainRule(sni, 10, false)},
			clientHello, addrRuleTCPTimeout, 1, 1,
		},
		{
			"tls: an ip literal sni is not matched as a domain",
			[]*config.Rule{domainRule(ipLiteral, 20, false)},
			ipLiteralHello, 0, 0, 1,
		},
		{
			"tls: an ip literal sni is not matched as a domain even by a block rule",
			[]*config.Rule{addrRule, domainRule(ipLiteral, 20, true)},
			ipLiteralHello, addrRuleTCPTimeout, 1, 1,
		},
		{
			"plain tcp: an address rule applies",
			[]*config.Rule{addrRule},
			plain, addrRuleTCPTimeout, 0, 1,
		},
		{
			"plain tcp: a domain rule does not apply, there is no name",
			[]*config.Rule{addrRule, domainRule(sni, 20, false)},
			plain, addrRuleTCPTimeout, 0, 1,
		},
		{
			"plain tcp: a domain block rule does not block, there is no name",
			[]*config.Rule{domainRule(sni, 20, true)},
			plain, 0, 0, 1,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			rs := rule.NewRuleSet()
			for _, r := range tc.rules {
				require.NoError(t, rs.Add(r))
			}

			hops := &hopRegistrar{}
			h := NewTCPHandler(
				zerolog.Nop(),
				desync.NewTLSDesyncer(zerolog.Nop(), nil, hops, nil, nil),
				rs,
				&config.RuntimeConfig{},
			)

			lConn, peer := net.Pipe()
			defer func() { _ = peer.Close() }()

			sysNet := &deadlineRecordingSysNet{}
			dst := &netutil.Destination{
				Addrs: []net.IP{net.ParseIP(dstIP)},
				Port:  443,
			}

			go func() { _, _ = peer.Write(tc.firstData) }()

			started := time.Now()
			done := make(chan struct{})
			go func() {
				h.Handle(context.Background(), lConn, dst, sysNet)
				close(done)
			}()

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("Handle did not return")
			}

			require.Equal(t, tc.wantDials, sysNet.dials.Load())
			assert.Equal(t, tc.wantHopReg, hops.registrations())

			deadline := *sysNet.deadline.Load()
			if tc.wantTimeout == 0 {
				assert.True(t, deadline.IsZero(), "deadline %v", deadline)
				return
			}
			assert.WithinDuration(t, started.Add(tc.wantTimeout), deadline, timeoutTolerance)
		})
	}
}
