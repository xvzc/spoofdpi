package http

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/desync"
	"github.com/xvzc/spoofdpi/internal/dns"
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

// newTestProxy returns an HTTPProxy that resolves names with resolver and
// selects rules from rs over base. listenAddr is the address the proxy
// takes as its own when it checks a destination.
func newTestProxy(
	logger zerolog.Logger,
	resolver dns.Resolver,
	rs *rule.RuleSet,
	base *config.RuntimeConfig,
	listenAddr net.TCPAddr,
) *HTTPProxy {
	return NewHTTPProxy(
		logger,
		NewHTTPHandler(logger, resolver, rs, listenAddr, base),
		NewHTTPSHandler(
			logger,
			desync.NewTLSDesyncer(zerolog.Nop(), nil, nil, nil),
			resolver,
			rs,
			listenAddr,
			base,
		),
		listenAddr,
	).(*HTTPProxy)
}

// runConn runs p.handleNewConnection on one end of a pipe and returns the
// other end, and a channel that is closed when the handler returns.
func runConn(t *testing.T, p *HTTPProxy) (net.Conn, <-chan struct{}) {
	t.Helper()

	client, srv := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))

	done := make(chan struct{})
	go func() {
		p.handleNewConnection(context.Background(), srv)
		close(done)
	}()

	return client, done
}

// startTCPEcho runs a loopback TCP server that echoes what it reads, and
// counts the connections it accepts.
func startTCPEcho(t *testing.T) (*net.TCPAddr, *atomic.Int32) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	var accepted atomic.Int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func() {
				defer func() { _ = conn.Close() }()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()

	return ln.Addr().(*net.TCPAddr), &accepted
}

// readStatus reads the head of one HTTP response from r and returns its
// status, such as "200 Connection Established".
func readStatus(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	res, err := http.ReadResponse(r, nil)
	require.NoError(t, err)
	return res.Status
}

// connectRequest returns a CONNECT request for host and port.
func connectRequest(host string, port int) string {
	target := net.JoinHostPort(host, strconv.Itoa(port))
	return "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n"
}

// getRequest returns a proxy GET request for path on host and port.
func getRequest(host string, port int, path string) string {
	target := net.JoinHostPort(host, strconv.Itoa(port))
	return "GET http://" + target + path + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n"
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
		addrs       []netip.Addr // what the resolver answers
		lookupErr   error        // the resolver's error
		wantReply   string       // "" when the conn is closed without a reply
		wantLookup  string       // HTTPSURL tag of the lookup's options, "" for none
		wantLogPart string
	}{
		{
			name:        "lookup error is a bad gateway",
			host:        "other.test",
			lookupErr:   errors.New("lookup failed"),
			wantReply:   "HTTP/1.1 502",
			wantLookup:  "base",
			wantLogPart: "dns lookup failed for other.test",
		},
		{
			name:       "domain rule blocks and sets the lookup options",
			host:       "blocked.test",
			addrs:      []netip.Addr{netip.MustParseAddr("198.51.100.1")},
			wantLookup: "rule",
		},
		{
			name:       "address rule blocks a resolved name",
			host:       "other.test",
			addrs:      []netip.Addr{netip.MustParseAddr("192.0.2.7")},
			wantLookup: "base",
		},
		{
			name:        "empty host is a bad gateway",
			host:        "",
			wantReply:   "HTTP/1.1 502",
			wantLogPart: "dns lookup failed for ",
		},
		{
			name:        "ip literal is not looked up",
			host:        "192.0.2.1",
			wantLogPart: `skipping dns lookup for non-domain host \"192.0.2.1\"`,
		},
	}

	requests := []struct {
		method string
		build  func(host string) string
	}{
		{"CONNECT", func(host string) string { return connectRequest(host, 443) }},
		{"GET", func(host string) string { return getRequest(host, 80, "/") }},
	}

	for _, req := range requests {
		for _, tc := range tcs {
			t.Run(req.method+"/"+tc.name, func(t *testing.T) {
				rs := rule.NewRuleSet()
				require.NoError(t, rs.Add(blockDomain))
				require.NoError(t, rs.Add(blockAddr))
				base := &config.RuntimeConfig{}
				base.DNS.HTTPSURL = "base"
				resolver := &fakeResolver{addrs: tc.addrs, err: tc.lookupErr}

				var logs bytes.Buffer
				p := newTestProxy(
					zerolog.New(zerolog.SyncWriter(&logs)).Level(zerolog.TraceLevel),
					resolver,
					rs,
					base,
					net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
				)

				client, done := runConn(t, p)
				_, err := client.Write([]byte(req.build(tc.host)))
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
					assert.Empty(t, resolver.lookups)
				} else if assert.Len(t, resolver.lookups, 1) {
					assert.Equal(t, tc.wantLookup, resolver.lookups[0].HTTPSURL)
				}

				if tc.wantLogPart != "" {
					assert.Contains(t, logs.String(), tc.wantLogPart)
				}
			})
		}
	}
}

func TestHTTPProxy_HandleNewConnection_PlainHTTP(t *testing.T) {
	echo, accepted := startTCPEcho(t)
	resolver := &fakeResolver{addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	p := newTestProxy(
		zerolog.Nop(),
		resolver,
		rule.NewRuleSet(),
		&config.RuntimeConfig{},
		net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
	)

	client, done := runConn(t, p)
	_, err := client.Write([]byte(getRequest("origin.test", echo.Port, "/path")))
	require.NoError(t, err)

	// The upstream echoes back the request the proxy forwarded to it.
	fwd, err := http.ReadRequest(bufio.NewReader(client))
	require.NoError(t, err)
	assert.Equal(t, http.MethodGet, fwd.Method)
	assert.Equal(t, "/path", fwd.URL.Path)
	assert.Equal(t, net.JoinHostPort("origin.test", strconv.Itoa(echo.Port)), fwd.Host)

	_ = client.Close()
	<-done

	assert.Equal(t, int32(1), accepted.Load())
	assert.Len(t, resolver.lookups, 1)
}

func TestHTTPProxy_HandleNewConnection_Connect(t *testing.T) {
	echo, accepted := startTCPEcho(t)
	resolver := &fakeResolver{}
	p := newTestProxy(
		zerolog.Nop(),
		resolver,
		rule.NewRuleSet(),
		&config.RuntimeConfig{},
		net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
	)

	client, done := runConn(t, p)
	br := bufio.NewReader(client)
	_, err := client.Write([]byte(connectRequest(echo.IP.String(), echo.Port)))
	require.NoError(t, err)

	assert.Equal(t, "200 Connection Established", readStatus(t, br))

	// The ClientHello reaches the upstream, which echoes it back.
	hello := []byte(config.FakeClientHello)
	_, err = client.Write(hello)
	require.NoError(t, err)
	got := make([]byte, len(hello))
	_, err = io.ReadFull(br, got)
	require.NoError(t, err)
	assert.Equal(t, hello, got)

	// Then the conns are tunneled.
	_, err = client.Write([]byte("ping"))
	require.NoError(t, err)
	got = make([]byte, 4)
	_, err = io.ReadFull(br, got)
	require.NoError(t, err)
	assert.Equal(t, "ping", string(got))

	_ = client.Close()
	<-done

	assert.Equal(t, int32(1), accepted.Load())
	assert.Empty(t, resolver.lookups, "an ip literal is not looked up")
}

// A destination at the proxy's own address gets a 403, and then the
// request is handled anyway.
// BUG: the 403 doesn't stop the request. This pins the current behavior.
func TestHTTPProxy_HandleNewConnection_ForbiddenKeepsGoing(t *testing.T) {
	t.Run("CONNECT", func(t *testing.T) {
		echo, accepted := startTCPEcho(t)
		p := newTestProxy(
			zerolog.Nop(),
			&fakeResolver{},
			rule.NewRuleSet(),
			&config.RuntimeConfig{},
			*echo, // the destination is the proxy itself
		)

		client, done := runConn(t, p)
		br := bufio.NewReader(client)
		_, err := client.Write([]byte(connectRequest(echo.IP.String(), echo.Port)))
		require.NoError(t, err)

		assert.Equal(t, "403 Forbidden", readStatus(t, br))
		assert.Equal(t, "200 Connection Established", readStatus(t, br))

		hello := []byte(config.FakeClientHello)
		_, err = client.Write(hello)
		require.NoError(t, err)
		got := make([]byte, len(hello))
		_, err = io.ReadFull(br, got)
		require.NoError(t, err)
		assert.Equal(t, hello, got)

		_ = client.Close()
		<-done

		assert.Equal(t, int32(1), accepted.Load())
	})

	t.Run("GET", func(t *testing.T) {
		echo, accepted := startTCPEcho(t)
		p := newTestProxy(
			zerolog.Nop(),
			&fakeResolver{},
			rule.NewRuleSet(),
			&config.RuntimeConfig{},
			*echo, // the destination is the proxy itself
		)

		client, done := runConn(t, p)
		br := bufio.NewReader(client)
		_, err := client.Write([]byte(getRequest(echo.IP.String(), echo.Port, "/")))
		require.NoError(t, err)

		assert.Equal(t, "403 Forbidden", readStatus(t, br))
		fwd, err := http.ReadRequest(br)
		require.NoError(t, err)
		assert.Equal(t, http.MethodGet, fwd.Method)

		_ = client.Close()
		<-done

		assert.Equal(t, int32(1), accepted.Load())
	})
}

// A second plain request on the same conn goes to the first request's
// upstream as is: it is neither resolved nor checked against the rules.
// BUG: each request should get its own destination and rule. This pins
// the current behavior.
func TestHTTPProxy_HandleNewConnection_KeepAliveReusesFirstHost(t *testing.T) {
	echo, accepted := startTCPEcho(t)
	resolver := &fakeResolver{addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	rs := rule.NewRuleSet()
	require.NoError(t, rs.Add(&config.Rule{
		Name:     "block second",
		Priority: 10,
		Block:    true,
		Match:    &config.MatchAttrs{Domains: []string{"second.test"}},
	}))
	p := newTestProxy(
		zerolog.Nop(),
		resolver,
		rs,
		&config.RuntimeConfig{},
		net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
	)

	client, done := runConn(t, p)
	br := bufio.NewReader(client)

	_, err := client.Write([]byte(getRequest("first.test", echo.Port, "/one")))
	require.NoError(t, err)
	first, err := http.ReadRequest(br)
	require.NoError(t, err)
	assert.Equal(t, "/one", first.URL.Path)

	_, err = client.Write([]byte(getRequest("second.test", 80, "/two")))
	require.NoError(t, err)
	second, err := http.ReadRequest(br)
	require.NoError(t, err)
	assert.Equal(t, "second.test:80", second.Host)
	assert.Equal(t, "/two", second.URL.Path)

	_ = client.Close()
	<-done

	assert.Equal(t, int32(1), accepted.Load())
	assert.Len(t, resolver.lookups, 1, "only the first host is looked up")
}
