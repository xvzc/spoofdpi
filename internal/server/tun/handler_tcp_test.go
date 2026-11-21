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
	domainRule := func(domain string, block bool) *config.Rule {
		return &config.Rule{
			Name:     "domain",
			Priority: 5,
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
			[]*config.Rule{addrRule(true), domainRule("other.test", false)},
			clientHello,
			0,
		},
		{"domain block by sni", []*config.Rule{domainRule(sni, true)}, clientHello, 0},
		{
			"domain block by sni over an allowing address rule",
			[]*config.Rule{addrRule(false), domainRule(sni, true)},
			clientHello,
			0,
		},
		{
			"sni domain rule overrides an address block",
			[]*config.Rule{addrRule(true), domainRule(sni, false)},
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
