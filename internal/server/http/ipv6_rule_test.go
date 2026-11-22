package http

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/rule"
)

// startDualEcho runs TCP echo servers on 127.0.0.1 and [::1] at the same
// port, and counts the connections each accepts. It skips the test when the
// host has no IPv6 loopback or the port is taken on [::1].
func startDualEcho(t *testing.T) (port int, v4, v6 *atomic.Int32) {
	t.Helper()

	ln4, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln4.Close() })
	port = ln4.Addr().(*net.TCPAddr).Port

	ln6, err := net.Listen("tcp", net.JoinHostPort("::1", strconv.Itoa(port)))
	if err != nil {
		t.Skipf("no IPv6 loopback at port %d: %v", port, err)
	}
	t.Cleanup(func() { _ = ln6.Close() })

	serve := func(ln net.Listener, accepted *atomic.Int32) {
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
	}
	v4, v6 = new(atomic.Int32), new(atomic.Int32)
	go serve(ln4, v4)
	go serve(ln6, v6)

	return port, v4, v6
}

// ipv6Rule returns a rule matching match whose ipv6 is ipv6, nil when the
// rule inherits the global value, which is off.
func ipv6Rule(match config.MatchAttrs, ipv6 *bool) *config.Rule {
	r := &config.Rule{Name: "rule", Priority: 10, Match: &match, IPv6: ipv6}
	if ipv6 != nil {
		r.Config.IPv6 = *ipv6
	}
	return r
}

// A rule that sets ipv6 = false itself keeps its connections to IPv4: an
// IPv6 literal gets a 502, and the IPv6 addresses of a name are not
// dialed. A rule that inherits ipv6, and an IPv4-mapped literal, are not
// affected.
func TestHTTPProxy_HandleNewConnection_RuleIPv6Off(t *testing.T) {
	off := false
	port, v4, v6 := startDualEcho(t)

	loopback6 := config.MatchAttrs{CIDRs: []string{"::1/128"}}
	loopback4 := config.MatchAttrs{CIDRs: []string{"127.0.0.0/8"}}
	byName := config.MatchAttrs{Domains: []string{"dual.test"}}
	dual := []netip.Addr{netip.MustParseAddr("::1"), netip.MustParseAddr("127.0.0.1")}
	only6 := []netip.Addr{netip.MustParseAddr("::1")}

	tcs := []struct {
		name     string
		rule     *config.Rule
		host     string
		answer   []netip.Addr
		wantFail bool
		wantV4   int32
		wantV6   int32
	}{
		{
			"set off refuses an IPv6 literal",
			ipv6Rule(loopback6, &off),
			"::1",
			nil,
			true,
			0,
			0,
		},
		{
			"set off drops the IPv6 addresses of a name",
			ipv6Rule(byName, &off),
			"dual.test",
			dual,
			false,
			1,
			0,
		},
		{
			"set off refuses a name with IPv6 addresses only",
			ipv6Rule(byName, &off),
			"dual.test",
			only6,
			true,
			0,
			0,
		},
		{
			"inherited off proxies an IPv6 literal",
			ipv6Rule(loopback6, nil),
			"::1",
			nil,
			false,
			0,
			1,
		},
		{
			"set off proxies an IPv4-mapped literal",
			ipv6Rule(loopback4, &off),
			"::ffff:127.0.0.1",
			nil,
			false,
			1,
			0,
		},
	}

	for _, tc := range tcs {
		for _, connect := range []bool{false, true} {
			method := "GET"
			if connect {
				method = "CONNECT"
			}
			t.Run(method+" "+tc.name, func(t *testing.T) {
				v4Before, v6Before := v4.Load(), v6.Load()

				rs := rule.NewRuleSet()
				require.NoError(t, rs.Add(tc.rule))
				p := newTestProxy(
					zerolog.Nop(),
					&fakeResolver{addrs: tc.answer},
					rs,
					&config.RuntimeConfig{},
					net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
				)

				client, done := runConn(t, p)
				br := bufio.NewReader(client)
				req := getRequest(tc.host, port, "/")
				if connect {
					req = connectRequest(tc.host, port)
				}
				_, err := client.Write([]byte(req))
				require.NoError(t, err)

				switch {
				case tc.wantFail:
					assert.Equal(t, "502 Bad Gateway", readStatus(t, br))
				case connect:
					assert.Equal(t, "200 Connection Established", readStatus(t, br))
					// The ClientHello reaches the upstream, which echoes it.
					hello := []byte(config.FakeClientHello)
					_, err = client.Write(hello)
					require.NoError(t, err)
					_, err = io.ReadFull(br, make([]byte, len(hello)))
					require.NoError(t, err)
				default:
					// The upstream echoes back the forwarded request.
					fwd, err := http.ReadRequest(br)
					require.NoError(t, err)
					assert.Equal(t, http.MethodGet, fwd.Method)
				}

				_ = client.Close()
				<-done

				assert.Equal(t, tc.wantV4, v4.Load()-v4Before, "IPv4 connections")
				assert.Equal(t, tc.wantV6, v6.Load()-v6Before, "IPv6 connections")
			})
		}
	}
}

// A zoned link-local literal is an IPv6 address like any other: a rule that
// sets ipv6 = false refuses it.
func TestVerifyDestination_RuleIPv6OffZoned(t *testing.T) {
	off := false
	dst := &netutil.Destination{
		Host:  "fe80::1%lo0",
		Addrs: []net.IP{net.ParseIP("fe80::1")},
		Zone:  "lo0",
		Port:  443,
	}
	matched := ipv6Rule(config.MatchAttrs{CIDRs: []string{"fe80::/10"}}, &off)

	got := verifyDestination(
		zerolog.Nop(),
		dst,
		matched,
		&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
	)
	assert.Equal(t, destinationIPv4Only, got)
}
