package http

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/rule"
)

func TestHTTPProxy_ServeStopsWithIdleConnection(t *testing.T) {
	var logs bytes.Buffer
	p := &HTTPProxy{
		logger:     zerolog.New(zerolog.SyncWriter(&logs)),
		listenAddr: net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, p.Listen(ctx))

	served := make(chan error, 1)
	go func() { served <- p.Serve(ctx) }()

	// The client sends nothing, so its handler waits in the request read.
	client, err := net.Dial("tcp", p.listener.Addr().String())
	require.NoError(t, err)
	defer func() { _ = client.Close() }()
	require.Eventually(t, func() bool { return p.conns.Active() == 1 },
		time.Second, 5*time.Millisecond)

	start := time.Now()
	cancel()

	select {
	case err := <-served:
		assert.NoError(t, err)
		assert.Less(t, time.Since(start), 2*time.Second)
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after ctx was cancelled")
	}

	require.NoError(t, client.SetReadDeadline(time.Now().Add(time.Second)))
	_, err = client.Read(make([]byte, 1))
	require.Error(t, err)
	var netErr net.Error
	if errors.As(err, &netErr) {
		assert.False(t, netErr.Timeout(), "the client must see the conn closed")
	}

	// Serve has returned, so every handler has finished logging.
	assert.Empty(t, logs.String(), "closing an idle conn at shutdown logs nothing")
}

func TestHTTPProxy_ListenAddressInUse(t *testing.T) {
	taken, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer func() { _ = taken.Close() }()

	p := &HTTPProxy{
		logger:     zerolog.Nop(),
		listenAddr: *taken.Addr().(*net.TCPAddr),
	}

	assert.Error(t, p.Listen(context.Background()))
}

// fakeResolver answers every lookup with addrs and err, and records the
// DNS options of each lookup.
type fakeResolver struct {
	addrs []netip.Addr
	err   error

	lookups []*config.DNSOptions
}

func (r *fakeResolver) Resolve(
	_ context.Context,
	opts *config.DNSOptions,
	_ string,
) ([]netip.Addr, error) {
	r.lookups = append(r.lookups, opts)
	return r.addrs, r.err
}

func TestHTTPProxy_HandleNewConnection_RuleSelection(t *testing.T) {
	blockDomain := &config.Rule{
		Name:     "block domain",
		Priority: 10,
		Block:    true,
		Match:    &config.MatchAttrs{Domains: []string{"blocked.test"}},
	}
	blockDomain.Config.DNS.HTTPSURL = "rule"
	blockAddr := &config.Rule{
		Name:     "block addr",
		Priority: 10,
		Block:    true,
		Match:    &config.MatchAttrs{CIDRs: []string{"192.0.2.0/24"}},
	}

	tcs := []struct {
		name        string
		host        string
		resolver    *fakeResolver
		wantReply   string // "" when the conn is closed without a reply
		wantLookup  string // HTTPSURL tag of the lookup's options, "" for none
		wantLogPart string
	}{
		{
			name:        "lookup error is a bad gateway",
			host:        "other.test",
			resolver:    &fakeResolver{err: errors.New("lookup failed")},
			wantReply:   "HTTP/1.1 502",
			wantLookup:  "base",
			wantLogPart: "dns lookup failed for other.test",
		},
		{
			name: "domain rule blocks and sets the lookup options",
			host: "blocked.test",
			resolver: &fakeResolver{
				addrs: []netip.Addr{netip.MustParseAddr("198.51.100.1")},
			},
			wantLookup: "rule",
		},
		{
			name:        "ip literal is not looked up",
			host:        "192.0.2.1",
			resolver:    &fakeResolver{},
			wantLogPart: `skipping dns lookup for non-domain host \"192.0.2.1\"`,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			rs := rule.NewRuleSet()
			require.NoError(t, rs.Add(blockDomain))
			require.NoError(t, rs.Add(blockAddr))
			base := &config.RuntimeConfig{}
			base.DNS.HTTPSURL = "base"

			var logs bytes.Buffer
			p := &HTTPProxy{
				logger: zerolog.New(zerolog.SyncWriter(&logs)).
					Level(zerolog.TraceLevel),
				resolver:   tc.resolver,
				ruleSet:    rs,
				listenAddr: net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
				cfg:        base,
			}

			client, srv := net.Pipe()
			defer func() { _ = client.Close() }()
			done := make(chan struct{})
			go func() {
				p.handleNewConnection(context.Background(), srv)
				close(done)
			}()

			target := net.JoinHostPort(tc.host, "443")
			_, err := client.Write([]byte(
				"CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n",
			))
			require.NoError(t, err)

			reply, _ := io.ReadAll(client)
			<-done

			if tc.wantReply == "" {
				assert.Empty(t, reply)
			} else {
				assert.True(t, strings.HasPrefix(string(reply), tc.wantReply),
					"reply %q", reply)
			}

			if tc.wantLookup == "" {
				assert.Empty(t, tc.resolver.lookups)
			} else if assert.Len(t, tc.resolver.lookups, 1) {
				assert.Equal(t, tc.wantLookup, tc.resolver.lookups[0].HTTPSURL)
			}

			if tc.wantLogPart != "" {
				assert.Contains(t, logs.String(), tc.wantLogPart)
			}
		})
	}
}
