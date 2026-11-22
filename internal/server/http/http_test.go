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
			desync.NewTLSDesyncer(zerolog.Nop(), nil, nil, nil, nil),
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

// A CONNECT to a link-local address with its zone, encoded as RFC 6874
// does, reaches the address through the interface the zone names.
func TestHTTPProxy_HandleNewConnection_ConnectLinkLocal(t *testing.T) {
	ln := listenLinkLocalLoopback(t)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	echo := ln.Addr().(*net.TCPAddr)

	resolver := &fakeResolver{err: errors.New("lookup failed")}
	p := newTestProxy(
		zerolog.Nop(),
		resolver,
		rule.NewRuleSet(),
		&config.RuntimeConfig{},
		net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
	)

	client, done := runConn(t, p)
	br := bufio.NewReader(client)
	host := echo.IP.String() + "%25" + echo.Zone
	_, err := client.Write([]byte(connectRequest(host, echo.Port)))
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

	_ = client.Close()
	<-done
	assert.Empty(t, resolver.lookups, "an ip literal is not looked up")
}

func TestResolveDestination_Zone(t *testing.T) {
	tcs := []struct {
		host     string
		wantIP   string
		wantZone string
	}{
		{"fe80::1%en0", "fe80::1", "en0"},
		{"fe80::1", "fe80::1", ""},
		{"192.0.2.1", "192.0.2.1", ""},
	}
	for _, tc := range tcs {
		t.Run(tc.host, func(t *testing.T) {
			resolver := &fakeResolver{err: errors.New("lookup failed")}
			dst, _, _, err := resolveDestination(
				context.Background(),
				zerolog.Nop(),
				resolver,
				rule.NewRuleSet(),
				&config.RuntimeConfig{},
				tc.host,
				443,
			)
			require.NoError(t, err)
			require.Len(t, dst.Addrs, 1)
			assert.Equal(t, tc.wantIP, dst.Addrs[0].String())
			assert.Equal(t, tc.wantZone, dst.Zone)
			assert.Empty(t, resolver.lookups, "an ip literal is not looked up")
		})
	}
}

// A destination at the proxy's own address gets a 403, and then the conn
// is closed without dialing anything.
func TestHTTPProxy_HandleNewConnection_ForbiddenSelf(t *testing.T) {
	requests := []struct {
		method string
		build  func(addr *net.TCPAddr) string
	}{
		{"CONNECT", func(addr *net.TCPAddr) string {
			return connectRequest(addr.IP.String(), addr.Port)
		}},
		{"GET", func(addr *net.TCPAddr) string {
			return getRequest(addr.IP.String(), addr.Port, "/")
		}},
	}

	for _, req := range requests {
		t.Run(req.method, func(t *testing.T) {
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
			_, err := client.Write([]byte(req.build(echo)))
			require.NoError(t, err)

			assert.Equal(t, "403 Forbidden", readStatus(t, br))
			rest, err := io.ReadAll(br)
			require.NoError(t, err, "the conn is closed after the 403")
			assert.Empty(t, rest)
			<-done

			assert.Equal(t, int32(0), accepted.Load(), "the upstream is not dialed")
		})
	}
}

// An unspecified destination, which Go dials as the local host, gets a 403
// on any port, and is not dialed.
func TestHTTPProxy_HandleNewConnection_ForbiddenUnspecified(t *testing.T) {
	echo, accepted := startTCPEcho(t)
	listens := []struct {
		name   string
		listen net.TCPAddr
	}{
		{"the listen port", *echo},
		{"another port", net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}},
	}

	for _, host := range []string{"0.0.0.0", "::"} {
		for _, l := range listens {
			for _, build := range []func(string, int) string{
				connectRequest,
				func(host string, port int) string { return getRequest(host, port, "/") },
			} {
				p := newTestProxy(
					zerolog.Nop(),
					&fakeResolver{},
					rule.NewRuleSet(),
					&config.RuntimeConfig{},
					l.listen,
				)
				req := build(host, echo.Port)
				t.Run(host+" on "+l.name+": "+strings.Fields(req)[0], func(t *testing.T) {
					client, done := runConn(t, p)
					br := bufio.NewReader(client)
					_, err := client.Write([]byte(req))
					require.NoError(t, err)

					// require: a tunnel opened by mistake would keep done
					// open.
					require.Equal(t, "403 Forbidden", readStatus(t, br))
					<-done
				})
			}
		}
	}

	assert.Equal(t, int32(0), accepted.Load(), "the upstream is not dialed")
}

// startHTTPOrigin runs a loopback HTTP/1.1 server that answers every request
// with "200 OK" and sends each request it reads on the returned channel. It
// keeps a connection open between requests unless a request asks to close
// it, and counts the connections it accepts.
func startHTTPOrigin(t *testing.T) (*net.TCPAddr, *atomic.Int32, <-chan *http.Request) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	var accepted atomic.Int32
	reqs := make(chan *http.Request, 16)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func() {
				defer func() { _ = conn.Close() }()
				br := bufio.NewReader(conn)
				for {
					req, err := http.ReadRequest(br)
					if err != nil {
						return
					}
					reqs <- req
					res := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
					if req.Close {
						res += "Connection: close\r\n"
					}
					if _, err := io.WriteString(conn, res+"\r\nok"); err != nil || req.Close {
						return
					}
				}
			}()
		}
	}()

	return ln.Addr().(*net.TCPAddr), &accepted, reqs
}

// A bracketed IPv6 literal without a port is an address, not a name to
// look up.
func TestHTTPProxy_HandleNewConnection_BracketedHostWithoutPort(t *testing.T) {
	requests := []string{
		"GET / HTTP/1.1\r\nHost: [::1]\r\n\r\n",
		"CONNECT [::1] HTTP/1.1\r\nHost: [::1]\r\n\r\n",
	}
	for _, req := range requests {
		t.Run(strings.Fields(req)[0], func(t *testing.T) {
			resolver := &fakeResolver{err: errors.New("lookup failed")}
			// An address rule for ::1 blocks the request before any dial, so
			// the test reaches no local service; that it applies shows the
			// host was taken as the address ::1.
			rs := rule.NewRuleSet()
			require.NoError(t, rs.Add(&config.Rule{
				Name:     "block ::1",
				Priority: 10,
				Block:    true,
				Match:    &config.MatchAttrs{CIDRs: []string{"::1/128"}},
			}))
			p := newTestProxy(
				zerolog.Nop(),
				resolver,
				rs,
				&config.RuntimeConfig{},
				net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
			)

			client, done := runConn(t, p)
			_, err := client.Write([]byte(req))
			require.NoError(t, err)

			// A blocked request is closed without a reply; a 502 would mean
			// the host went to the resolver.
			reply, err := io.ReadAll(client)
			require.NoError(t, err)
			<-done

			assert.Empty(t, reply)
			assert.Empty(t, resolver.lookups, "an ip literal is not looked up")
		})
	}
}

// A plain request is forwarded with "Connection: close", and the client conn
// is closed after the response, so a later request comes on a new conn and
// gets its own rule.
func TestHTTPProxy_HandleNewConnection_PlainRequestClosesConn(t *testing.T) {
	origin, accepted, reqs := startHTTPOrigin(t)
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

	first := net.JoinHostPort("first.test", strconv.Itoa(origin.Port))
	client, done := runConn(t, p)
	br := bufio.NewReader(client)
	_, err := client.Write([]byte("GET http://" + first + "/one HTTP/1.1\r\n" +
		"Host: " + first + "\r\n" +
		"Connection: keep-alive\r\n" +
		"Keep-Alive: timeout=5\r\n" +
		"Proxy-Connection: keep-alive\r\n\r\n"))
	require.NoError(t, err)

	res, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	assert.Equal(t, "200 OK", res.Status)
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	assert.Equal(t, "ok", string(body))

	rest, err := io.ReadAll(br)
	require.NoError(t, err, "the conn is closed after the response")
	assert.Empty(t, rest)
	<-done

	fwd := <-reqs
	assert.Equal(t, "/one", fwd.URL.Path)
	assert.Equal(t, []string{"close"}, fwd.Header.Values("Connection"))
	assert.Empty(t, fwd.Header.Values("Keep-Alive"))
	assert.Empty(t, fwd.Header.Values("Proxy-Connection"))

	// The second request comes on a new conn, where its rule blocks it.
	client, done = runConn(t, p)
	_, err = client.Write([]byte(getRequest("second.test", origin.Port, "/two")))
	require.NoError(t, err)
	reply, err := io.ReadAll(client)
	require.NoError(t, err)
	assert.Empty(t, reply, "a blocked request is closed without a reply")
	<-done

	assert.Equal(t, int32(1), accepted.Load())
	assert.Len(t, resolver.lookups, 2, "each request is looked up")
}

// A request that upgrades the conn is forwarded as is, and then the conns
// are tunneled.
func TestHTTPProxy_HandleNewConnection_PlainUpgradeTunnels(t *testing.T) {
	echo, accepted := startTCPEcho(t)
	p := newTestProxy(
		zerolog.Nop(),
		&fakeResolver{addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}},
		rule.NewRuleSet(),
		&config.RuntimeConfig{},
		net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
	)

	target := net.JoinHostPort("origin.test", strconv.Itoa(echo.Port))
	client, done := runConn(t, p)
	br := bufio.NewReader(client)
	_, err := client.Write([]byte("GET http://" + target + "/ws HTTP/1.1\r\n" +
		"Host: " + target + "\r\n" +
		"Connection: Upgrade\r\n" +
		"Upgrade: websocket\r\n\r\n"))
	require.NoError(t, err)

	// The upstream echoes back the request the proxy forwarded to it.
	fwd, err := http.ReadRequest(br)
	require.NoError(t, err)
	assert.Equal(t, []string{"Upgrade"}, fwd.Header.Values("Connection"))
	assert.Equal(t, "websocket", fwd.Header.Get("Upgrade"))

	_, err = client.Write([]byte("ping"))
	require.NoError(t, err)
	got := make([]byte, 4)
	_, err = io.ReadFull(br, got)
	require.NoError(t, err)
	assert.Equal(t, "ping", string(got))

	_ = client.Close()
	<-done

	assert.Equal(t, int32(1), accepted.Load())
}

// startUnreachableTCP returns the address of a loopback listener that never
// accepts and whose backlog is full, so a connect to it does not complete,
// for longer than any timeout a test sets, until the connect is canceled.
func startUnreachableTCP(t *testing.T) *net.TCPAddr {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	addr := ln.Addr().String()

	// Connect until one does not complete, which is when the backlog is full.
	const maxConns = 1 << 16
	for range maxConns {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err != nil {
			return ln.Addr().(*net.TCPAddr)
		}
		t.Cleanup(func() { _ = conn.Close() })
	}
	t.Fatal("the listener backlog did not fill up")
	return nil
}

// A plain request is dialed with the TCP timeout of the config its rule
// selects: against a target the connect never completes at, the rule's
// short timeout ends the dial with a prompt 502, while the base config,
// which has no timeout, keeps dialing.
func TestHTTPProxy_HandleNewConnection_PlainDialTimeoutFromRule(t *testing.T) {
	unreachable := startUnreachableTCP(t)
	slow := &config.Rule{
		Name:     "slow",
		Priority: 10,
		Match:    &config.MatchAttrs{Domains: []string{"slow.test"}},
	}
	const ruleTimeout = 100 * time.Millisecond
	slow.Config.Conn.TCPTimeout = ruleTimeout
	rs := rule.NewRuleSet()
	require.NoError(t, rs.Add(slow))
	p := newTestProxy(
		zerolog.Nop(),
		&fakeResolver{addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}},
		rs,
		&config.RuntimeConfig{},
		net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
	)

	t.Run("rule timeout ends the dial", func(t *testing.T) {
		client, done := runConn(t, p)
		started := time.Now()
		_, err := client.Write([]byte(getRequest("slow.test", unreachable.Port, "/")))
		require.NoError(t, err)

		reply, err := io.ReadAll(client)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(string(reply), "HTTP/1.1 502"), "reply %q", reply)
		assert.GreaterOrEqual(t, time.Since(started), ruleTimeout)
		<-done
	})

	t.Run("base config keeps dialing", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		client, srv := net.Pipe()
		t.Cleanup(func() { _ = client.Close() })
		done := make(chan struct{})
		go func() {
			p.handleNewConnection(ctx, srv)
			close(done)
		}()

		_, err := client.Write([]byte(getRequest("base.test", unreachable.Port, "/")))
		require.NoError(t, err)

		// Ten times the rule's timeout has passed without the dial ending.
		select {
		case <-done:
			t.Fatal("the dial without a timeout ended")
		case <-time.After(10 * ruleTimeout):
		}

		// Canceling the dial is what ends it, with the 502 the client reads.
		cancel()
		require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
		reply, err := io.ReadAll(client)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(string(reply), "HTTP/1.1 502"), "reply %q", reply)
		<-done
	})
}

// listenLinkLocalLoopback returns a TCP listener on the IPv6 link-local
// address of a loopback interface, such as fe80::1%lo0, or skips the test
// when the host has none.
func listenLinkLocalLoopback(t *testing.T) net.Listener {
	t.Helper()

	ifaces, err := net.Interfaces()
	require.NoError(t, err)
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok || ipNet.IP.To4() != nil || !ipNet.IP.IsLinkLocalUnicast() {
				continue
			}
			host := ipNet.IP.String() + "%" + iface.Name
			ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
			if err == nil {
				return ln
			}
		}
	}
	t.Skip("no IPv6 link-local address on a loopback interface")
	return nil
}
