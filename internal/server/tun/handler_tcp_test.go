package tun

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/desync"
	"github.com/xvzc/spoofdpi/internal/netutil"
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
				desync.NewTLSDesyncer(zerolog.Nop(), nil, nil, nil),
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
