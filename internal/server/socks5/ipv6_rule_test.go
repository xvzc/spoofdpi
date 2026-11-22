package socks5

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/desync"
	"github.com/xvzc/spoofdpi/internal/proto"
	"github.com/xvzc/spoofdpi/internal/rule"
	"github.com/xvzc/spoofdpi/internal/server"
)

// startDualTCPEcho runs TCP echo servers on 127.0.0.1 and [::1] at the same
// port, and counts the connections each accepts. It skips the test when the
// host has no IPv6 loopback or the port is taken on [::1].
func startDualTCPEcho(t *testing.T) (port int, v4, v6 *atomic.Int32) {
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
	r.Config.Conn.TCPTimeout = 2 * time.Second
	return r
}

var (
	loopback6Match = config.MatchAttrs{CIDRs: []string{"::1/128"}}
	loopback4Match = config.MatchAttrs{CIDRs: []string{"127.0.0.0/8"}}
	dualNameMatch  = config.MatchAttrs{Domains: []string{"dual.test"}}
)

// A rule that sets ipv6 = false itself keeps its connections to IPv4: an
// IPv6 destination gets "connection not allowed by ruleset", and the IPv6
// addresses of a name are not dialed. A rule that inherits ipv6, and an
// IPv4-mapped literal, are not affected.
func TestConnectHandler_Handle_RuleIPv6Off(t *testing.T) {
	off := false
	port, v4, v6 := startDualTCPEcho(t)

	atyp6 := func(ip string) *proto.SOCKS5Request {
		return &proto.SOCKS5Request{
			Cmd:  proto.SOCKS5CmdConnect,
			ATYP: proto.SOCKS5AddrTypeIPv6,
			IP:   net.ParseIP(ip),
			Port: port,
		}
	}
	byName := func(name string) *proto.SOCKS5Request {
		return &proto.SOCKS5Request{
			Cmd:  proto.SOCKS5CmdConnect,
			ATYP: proto.SOCKS5AddrTypeFQDN,
			FQDN: name,
			Port: port,
		}
	}
	dual := []netip.Addr{netip.MustParseAddr("::1"), netip.MustParseAddr("127.0.0.1")}
	only6 := []netip.Addr{netip.MustParseAddr("::1")}

	tcs := []struct {
		name     string
		rule     *config.Rule
		req      *proto.SOCKS5Request
		answer   []netip.Addr
		wantFail bool
		wantV4   int32
		wantV6   int32
	}{
		{
			"set off refuses ATYP 4",
			ipv6Rule(loopback6Match, &off),
			atyp6("::1"),
			nil,
			true,
			0,
			0,
		},
		{
			"set off refuses an IPv6 literal name",
			ipv6Rule(loopback6Match, &off),
			byName("::1"),
			nil,
			true,
			0,
			0,
		},
		{
			"set off drops the IPv6 addresses of a name",
			ipv6Rule(dualNameMatch, &off),
			byName("dual.test"),
			dual,
			false,
			1,
			0,
		},
		{
			"set off refuses a name with IPv6 addresses only",
			ipv6Rule(dualNameMatch, &off),
			byName("dual.test"),
			only6,
			true,
			0,
			0,
		},
		{
			"set off refuses a zoned link-local name",
			ipv6Rule(config.MatchAttrs{CIDRs: []string{"fe80::/10"}}, &off),
			byName("fe80::1%lo0"),
			nil,
			true,
			0,
			0,
		},
		{
			"inherited off proxies ATYP 4",
			ipv6Rule(loopback6Match, nil),
			atyp6("::1"),
			nil,
			false,
			0,
			1,
		},
		{
			"set off proxies an IPv4-mapped literal name",
			ipv6Rule(loopback4Match, &off),
			byName("::ffff:127.0.0.1"),
			nil,
			false,
			1,
			0,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			v4Before, v6Before := v4.Load(), v6.Load()

			rs := rule.NewRuleSet()
			require.NoError(t, rs.Add(tc.rule))
			base := &config.RuntimeConfig{}
			base.Conn.TCPTimeout = 2 * time.Second
			h := NewConnectHandler(
				zerolog.Nop(),
				desync.NewTLSDesyncer(zerolog.Nop(), nil, nil, nil, nil),
				&multiAddrResolver{addrs: tc.answer},
				rs,
				net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
				base,
			)

			client, done := runConnect(t, h, tc.req)

			if tc.wantFail {
				assert.Equal(t, byte(proto.SOCKS5RCodeNotAllowed), readReply(t, client))
				assert.ErrorIs(t, <-done, server.ErrIPv4Only)
			} else {
				require.Equal(t, byte(proto.SOCKS5RCodeSuccess), readReply(t, client))
				_, err := client.Write([]byte("ping"))
				require.NoError(t, err)
				buf := make([]byte, 4)
				_, err = io.ReadFull(client, buf)
				require.NoError(t, err)
				assert.Equal(t, "ping", string(buf))
				_ = client.Close()
				<-done
			}

			assert.Equal(t, tc.wantV4, v4.Load()-v4Before, "IPv4 connections")
			assert.Equal(t, tc.wantV6, v6.Load()-v6Before, "IPv6 connections")
		})
	}
}

// Under a rule that sets ipv6 = false itself, a datagram to an IPv6
// destination is dropped, and a datagram to a name goes to its first IPv4
// address. A rule that inherits ipv6, and an IPv4-mapped literal, are not
// affected.
func TestUdpAssociateHandler_SelectRule_RuleIPv6Off(t *testing.T) {
	off := false
	doc6 := config.MatchAttrs{CIDRs: []string{"2001:db8::/32"}}
	doc4 := config.MatchAttrs{CIDRs: []string{"192.0.2.0/24"}}
	dual := []netip.Addr{
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("192.0.2.1"),
	}

	tcs := []struct {
		name   string
		rule   *config.Rule
		dst    string
		answer []netip.Addr
		want   string // "" when the datagram is dropped
	}{
		{
			"set off drops an IPv6 literal",
			ipv6Rule(doc6, &off),
			"[2001:db8::1]:443",
			nil,
			"",
		},
		{
			"set off sends a name to its first IPv4 address",
			ipv6Rule(dualNameMatch, &off),
			"dual.test:443",
			dual,
			"192.0.2.1:443",
		},
		{
			"set off drops a name with IPv6 addresses only",
			ipv6Rule(dualNameMatch, &off),
			"dual.test:443",
			dual[:1],
			"",
		},
		{
			"inherited off sends to an IPv6 literal",
			ipv6Rule(doc6, nil),
			"[2001:db8::1]:443",
			nil,
			"[2001:db8::1]:443",
		},
		{
			"set off sends to an IPv4-mapped literal",
			ipv6Rule(doc4, &off),
			"[::ffff:192.0.2.1]:443",
			nil,
			"192.0.2.1:443",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			rs := rule.NewRuleSet()
			require.NoError(t, rs.Add(tc.rule))
			h := NewUdpAssociateHandler(
				zerolog.Nop(),
				nil,
				&multiAddrResolver{addrs: tc.answer},
				rs,
				&config.RuntimeConfig{},
			)
			c := newUdpAssociateConn(h, nil, nil)
			c.logger = zerolog.Nop()

			dstAddr, _, ok := c.selectRule(context.Background(), tc.dst)
			if tc.want == "" {
				assert.False(t, ok)
				return
			}
			require.True(t, ok)
			assert.Equal(t, tc.want, dstAddr.String())
		})
	}
}

// A datagram that a rule with ipv6 = false sends to an IPv4 address
// instead selects its rule again by that address, so that a
// higher-priority rule for it applies: a block drops it, and another rule's
// settings apply to it.
func TestUdpAssociateHandler_SelectRule_RuleIPv6OffReselects(t *testing.T) {
	off := false
	v4Only := ipv6Rule(config.MatchAttrs{CIDRs: []string{"2001:db8::/32"}}, &off)
	v4Only.Config.Conn.UDPIdleTimeout = 3 * time.Second
	v4Range := func(block bool) *config.Rule {
		r := &config.Rule{
			Name:     "ipv4 range",
			Priority: 20,
			Block:    block,
			Match:    &config.MatchAttrs{CIDRs: []string{"192.0.2.0/24"}},
		}
		r.Config.Conn.UDPIdleTimeout = 7 * time.Second
		return r
	}
	dual := []netip.Addr{
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("192.0.2.1"),
	}

	selectRule := func(t *testing.T, rules ...*config.Rule) (*net.UDPAddr, *config.RuntimeConfig, bool) {
		t.Helper()
		rs := rule.NewRuleSet()
		for _, r := range rules {
			require.NoError(t, rs.Add(r))
		}
		h := NewUdpAssociateHandler(
			zerolog.Nop(),
			nil,
			&multiAddrResolver{addrs: dual},
			rs,
			&config.RuntimeConfig{},
		)
		c := newUdpAssociateConn(h, nil, nil)
		c.logger = zerolog.Nop()
		return c.selectRule(context.Background(), "dual.test:443")
	}

	t.Run("a block on the IPv4 address drops it", func(t *testing.T) {
		_, _, ok := selectRule(t, v4Only, v4Range(true))
		assert.False(t, ok)
	})

	t.Run("the rule for the IPv4 address applies", func(t *testing.T) {
		dstAddr, cfg, ok := selectRule(t, v4Only, v4Range(false))
		require.True(t, ok)
		assert.Equal(t, "192.0.2.1:443", dstAddr.String())
		assert.Equal(t, 7*time.Second, cfg.Conn.UDPIdleTimeout)
	})

	t.Run(
		"without a rule for the IPv4 address the first rule applies",
		func(t *testing.T) {
			dstAddr, cfg, ok := selectRule(t, v4Only)
			require.True(t, ok)
			assert.Equal(t, "192.0.2.1:443", dstAddr.String())
			assert.Equal(t, 3*time.Second, cfg.Conn.UDPIdleTimeout)
		},
	)
}
