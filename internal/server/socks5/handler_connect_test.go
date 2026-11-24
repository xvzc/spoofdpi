package socks5

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/desync"
	"github.com/xvzc/spoofdpi/internal/dns"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/proto"
	"github.com/xvzc/spoofdpi/internal/rule"
	"github.com/xvzc/spoofdpi/internal/server"
)

// fakeDNSServer answers every A query with answer and counts the queries.
type fakeDNSServer struct {
	addr    net.TCPAddr
	queries atomic.Int32
}

func startFakeDNSServer(t *testing.T, answer net.IP) *fakeDNSServer {
	t.Helper()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	udpAddr := conn.LocalAddr().(*net.UDPAddr)
	s := &fakeDNSServer{addr: net.TCPAddr{IP: udpAddr.IP, Port: udpAddr.Port}}

	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			req := new(mdns.Msg)
			if err := req.Unpack(buf[:n]); err != nil {
				continue
			}
			s.queries.Add(1)

			resp := new(mdns.Msg)
			resp.SetReply(req)
			resp.Answer = append(resp.Answer, &mdns.A{
				Hdr: mdns.RR_Header{
					Name:   req.Question[0].Name,
					Rrtype: mdns.TypeA,
					Class:  mdns.ClassINET,
					Ttl:    60,
				},
				A: answer,
			})
			out, err := resp.Pack()
			if err != nil {
				continue
			}
			_, _ = conn.WriteTo(out, from)
		}
	}()

	return s
}

func dnsOptionsFor(s *fakeDNSServer) config.DNSOptions {
	opts := config.DefaultConfig().DNS
	opts.Mode = config.DNSModeUDP
	opts.Addr = s.addr
	opts.QType = config.DNSQueryIPv4
	opts.Timeout = 2 * time.Second
	return opts
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

// runConnect runs h.Handle for req on a loopback connection and returns
// the client side, and a channel that delivers Handle's result.
func runConnect(
	t *testing.T,
	h *ConnectHandler,
	req *proto.SOCKS5Request,
) (net.Conn, <-chan error) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	client, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	srvConn, err := ln.Accept()
	require.NoError(t, err)
	t.Cleanup(func() { _ = srvConn.Close() })

	done := make(chan error, 1)
	go func() {
		done <- h.Handle(context.Background(), srvConn, req)
	}()

	return client, done
}

// readReply returns the reply code of the SOCKS5 reply on conn.
func readReply(t *testing.T, conn net.Conn) byte {
	t.Helper()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	// VER REP RSV ATYP(IPv4) ADDR(4) PORT(2)
	reply := make([]byte, 10)
	_, err := io.ReadFull(conn, reply)
	require.NoError(t, err)
	return reply[1]
}

func TestConnectHandler_Handle(t *testing.T) {
	const name = "target.test"

	echo, accepted := startTCPEcho(t)

	domainRule := func(priority uint16, block bool) *config.Rule {
		return &config.Rule{
			Name:     "domain",
			Priority: priority,
			Block:    block,
			Match:    &config.MatchAttrs{Domains: []string{name}},
		}
	}
	addrRule := func(priority uint16, block bool) *config.Rule {
		return &config.Rule{
			Name:     "addr",
			Priority: priority,
			Block:    block,
			Match:    &config.MatchAttrs{CIDRs: []string{"127.0.0.0/8"}},
		}
	}

	byName := &proto.SOCKS5Request{
		Cmd:  proto.SOCKS5CmdConnect,
		ATYP: proto.SOCKS5AddrTypeFQDN,
		FQDN: name,
		Port: echo.Port,
	}
	byAddr := &proto.SOCKS5Request{
		Cmd:  proto.SOCKS5CmdConnect,
		ATYP: proto.SOCKS5AddrTypeIPv4,
		IP:   echo.IP.To4(),
		Port: echo.Port,
	}

	tcs := []struct {
		name        string
		req         *proto.SOCKS5Request
		rules       []*config.Rule
		wantBlocked bool
		wantLookups int32 // through the base DNS options
	}{
		{"address, no rule", byAddr, nil, false, 0},
		{"name, no rule", byName, nil, false, 1},
		{"address block", byAddr, []*config.Rule{addrRule(10, true)}, true, 0},
		{"domain block", byName, []*config.Rule{domainRule(10, true)}, true, 1},
		{
			"higher-priority domain allow overrides an address block",
			byName,
			[]*config.Rule{addrRule(10, true), domainRule(20, false)},
			false,
			1,
		},
		{
			"higher-priority address block overrides a domain allow",
			byName,
			[]*config.Rule{addrRule(20, true), domainRule(10, false)},
			true,
			1,
		},
		{
			"address block wins a priority tie with a domain allow",
			byName,
			[]*config.Rule{addrRule(10, true), domainRule(10, false)},
			true,
			1,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			baseDNS := startFakeDNSServer(t, echo.IP)
			base := &config.RuntimeConfig{DNS: dnsOptionsFor(baseDNS)}
			base.Conn.TCPTimeout = 2 * time.Second

			rs := rule.NewRuleSet()
			for _, r := range tc.rules {
				// A rule's DNS options are the base's unless it overrides them.
				r.Config = *base
				require.NoError(t, rs.Add(r))
			}

			h := NewConnectHandler(
				zerolog.Nop(),
				desync.NewTLSDesyncer(zerolog.Nop(), nil, nil, nil, nil),
				server.NewTLSAlertWatcher(),
				dns.NewClient(zerolog.Nop(), &base.DNS),
				rs,
				net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
				base,
			)
			acceptedBefore := accepted.Load()

			client, done := runConnect(t, h, tc.req)

			if tc.wantBlocked {
				assert.Equal(t, byte(proto.SOCKS5RCodeGenFailure), readReply(t, client))
				assert.ErrorIs(t, <-done, netutil.ErrBlocked)
				assert.Equal(t, acceptedBefore, accepted.Load())
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
			assert.Equal(t, tc.wantLookups, baseDNS.queries.Load())
		})
	}
}

func TestConnectHandler_Handle_DomainDNSOverride(t *testing.T) {
	const name = "target.test"

	echo, _ := startTCPEcho(t)
	baseDNS := startFakeDNSServer(t, echo.IP)
	ruleDNS := startFakeDNSServer(t, echo.IP)

	base := &config.RuntimeConfig{DNS: dnsOptionsFor(baseDNS)}
	base.Conn.TCPTimeout = 2 * time.Second

	override := &config.Rule{
		Name:     "override dns",
		Priority: 10,
		Match:    &config.MatchAttrs{Domains: []string{name}},
		Config:   *base,
	}
	override.Config.DNS = dnsOptionsFor(ruleDNS)

	rs := rule.NewRuleSet()
	require.NoError(t, rs.Add(override))

	h := NewConnectHandler(
		zerolog.Nop(),
		desync.NewTLSDesyncer(zerolog.Nop(), nil, nil, nil, nil),
		server.NewTLSAlertWatcher(),
		dns.NewClient(zerolog.Nop(), &base.DNS),
		rs,
		net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
		base,
	)

	client, done := runConnect(t, h, &proto.SOCKS5Request{
		Cmd:  proto.SOCKS5CmdConnect,
		ATYP: proto.SOCKS5AddrTypeFQDN,
		FQDN: name,
		Port: echo.Port,
	})

	require.Equal(t, byte(proto.SOCKS5RCodeSuccess), readReply(t, client))
	_ = client.Close()
	<-done

	assert.Equal(t, int32(1), ruleDNS.queries.Load())
	assert.Equal(t, int32(0), baseDNS.queries.Load())
}

func TestConnectHandler_Handle_NoAddress(t *testing.T) {
	baseDNS := startFakeDNSServer(t, net.IPv4(127, 0, 0, 1))
	base := &config.RuntimeConfig{DNS: dnsOptionsFor(baseDNS)}

	h := NewConnectHandler(
		zerolog.Nop(),
		desync.NewTLSDesyncer(zerolog.Nop(), nil, nil, nil, nil),
		server.NewTLSAlertWatcher(),
		dns.NewClient(zerolog.Nop(), &base.DNS),
		rule.NewRuleSet(),
		net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
		base,
	)

	// A one-character name is not looked up, and no reply is sent.
	_, done := runConnect(t, h, &proto.SOCKS5Request{
		Cmd:  proto.SOCKS5CmdConnect,
		ATYP: proto.SOCKS5AddrTypeFQDN,
		FQDN: "x",
		Port: 443,
	})

	assert.NoError(t, <-done)
	assert.Equal(t, int32(0), baseDNS.queries.Load())
}

func TestConnectHandler_Handle_IPLiteralName(t *testing.T) {
	echo, _ := startTCPEcho(t)
	baseDNS := startFakeDNSServer(t, echo.IP)
	base := &config.RuntimeConfig{DNS: dnsOptionsFor(baseDNS)}
	base.Conn.TCPTimeout = 2 * time.Second

	literal := echo.IP.String()

	// A domain rule for the literal doesn't apply: an address sent as a
	// name is matched only as an address.
	rs := rule.NewRuleSet()
	require.NoError(t, rs.Add(&config.Rule{
		Name:     "literal as domain",
		Priority: 10,
		Block:    true,
		Match:    &config.MatchAttrs{Domains: []string{literal}},
	}))

	h := NewConnectHandler(
		zerolog.Nop(),
		desync.NewTLSDesyncer(zerolog.Nop(), nil, nil, nil, nil),
		server.NewTLSAlertWatcher(),
		dns.NewClient(zerolog.Nop(), &base.DNS),
		rs,
		net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
		base,
	)

	client, done := runConnect(t, h, &proto.SOCKS5Request{
		Cmd:  proto.SOCKS5CmdConnect,
		ATYP: proto.SOCKS5AddrTypeFQDN,
		FQDN: literal,
		Port: echo.Port,
	})

	require.Equal(t, byte(proto.SOCKS5RCodeSuccess), readReply(t, client))
	_ = client.Close()
	<-done

	assert.Equal(t, int32(0), baseDNS.queries.Load())
}

// A link-local destination without a zone can't be dialed, and a SOCKS5
// address has no zone, so it gets "address type not supported".
func TestConnectHandler_Handle_LinkLocalWithoutZone(t *testing.T) {
	reqs := []struct {
		name string
		req  *proto.SOCKS5Request
	}{
		{"address", &proto.SOCKS5Request{
			Cmd:  proto.SOCKS5CmdConnect,
			ATYP: proto.SOCKS5AddrTypeIPv6,
			IP:   net.ParseIP("fe80::1"),
			Port: 443,
		}},
		{"name", &proto.SOCKS5Request{
			Cmd:  proto.SOCKS5CmdConnect,
			ATYP: proto.SOCKS5AddrTypeFQDN,
			FQDN: "fe80::1",
			Port: 443,
		}},
	}
	for _, tc := range reqs {
		t.Run(tc.name, func(t *testing.T) {
			resolver := &stubResolver{}
			h := NewConnectHandler(
				zerolog.Nop(),
				desync.NewTLSDesyncer(zerolog.Nop(), nil, nil, nil, nil),
				server.NewTLSAlertWatcher(),
				resolver,
				rule.NewRuleSet(),
				net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
				&config.RuntimeConfig{},
			)

			client, done := runConnect(t, h, tc.req)
			require.Equal(
				t,
				byte(proto.SOCKS5RCodeAddrNotSupported),
				readReply(t, client),
			)
			assert.Error(t, <-done)
			assert.Equal(t, int32(0), resolver.lookups.Load())
		})
	}
}

// A link-local literal sent as a name carries its zone, so it is dialed
// through the interface the zone names.
func TestConnectHandler_Handle_LinkLocalNameWithZone(t *testing.T) {
	ln := listenLinkLocalLoopback(t)
	t.Cleanup(func() { _ = ln.Close() })
	var accepted atomic.Int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_ = conn.Close()
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)

	resolver := &stubResolver{}
	base := &config.RuntimeConfig{}
	base.Conn.TCPTimeout = 2 * time.Second
	h := NewConnectHandler(
		zerolog.Nop(),
		desync.NewTLSDesyncer(zerolog.Nop(), nil, nil, nil, nil),
		server.NewTLSAlertWatcher(),
		resolver,
		rule.NewRuleSet(),
		net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
		base,
	)

	client, done := runConnect(t, h, &proto.SOCKS5Request{
		Cmd:  proto.SOCKS5CmdConnect,
		ATYP: proto.SOCKS5AddrTypeFQDN,
		FQDN: addr.IP.String() + "%" + addr.Zone,
		Port: addr.Port,
	})

	require.Equal(t, byte(proto.SOCKS5RCodeSuccess), readReply(t, client))
	_ = client.Close()
	<-done

	assert.Equal(t, int32(1), accepted.Load())
	assert.Equal(t, int32(0), resolver.lookups.Load())
}

// An unspecified destination, which Go dials as the local host, gets a
// failure reply on any port, and is not dialed.
func TestConnectHandler_Handle_Unspecified(t *testing.T) {
	echo, accepted := startTCPEcho(t)
	listens := []struct {
		name   string
		listen net.TCPAddr
	}{
		{"the listen port", *echo},
		{"another port", net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}},
	}
	reqs := []*proto.SOCKS5Request{
		{
			Cmd:  proto.SOCKS5CmdConnect,
			ATYP: proto.SOCKS5AddrTypeIPv4,
			IP:   net.IPv4zero,
			Port: echo.Port,
		},
		{
			Cmd:  proto.SOCKS5CmdConnect,
			ATYP: proto.SOCKS5AddrTypeIPv6,
			IP:   net.IPv6unspecified,
			Port: echo.Port,
		},
	}

	for _, l := range listens {
		for _, req := range reqs {
			t.Run(req.IP.String()+" on "+l.name, func(t *testing.T) {
				h := NewConnectHandler(
					zerolog.Nop(),
					desync.NewTLSDesyncer(zerolog.Nop(), nil, nil, nil, nil),
					server.NewTLSAlertWatcher(),
					&stubResolver{},
					rule.NewRuleSet(),
					l.listen,
					&config.RuntimeConfig{},
				)

				client, done := runConnect(t, h, req)
				require.Equal(t, byte(proto.SOCKS5RCodeGenFailure), readReply(t, client))
				assert.Error(t, <-done)
			})
		}
	}

	assert.Equal(t, int32(0), accepted.Load(), "the upstream is not dialed")
}

func TestConnectHandler_Handle_LookupError(t *testing.T) {
	errLookup := errors.New("lookup failed")
	resolver := &stubResolver{errs: map[string]error{"fail.test": errLookup}}
	base := &config.RuntimeConfig{}

	h := NewConnectHandler(
		zerolog.Nop(),
		desync.NewTLSDesyncer(zerolog.Nop(), nil, nil, nil, nil),
		server.NewTLSAlertWatcher(),
		resolver,
		rule.NewRuleSet(),
		net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
		base,
	)

	_, done := runConnect(t, h, &proto.SOCKS5Request{
		Cmd:  proto.SOCKS5CmdConnect,
		ATYP: proto.SOCKS5AddrTypeFQDN,
		FQDN: "fail.test",
		Port: 443,
	})

	assert.ErrorIs(t, <-done, errLookup)
	assert.Equal(t, int32(1), resolver.lookups.Load())
	assert.Same(t, &base.DNS, resolver.lookupOpts("fail.test"))
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

func TestConnectHandler_Handle_TLSAlertReply(t *testing.T) {
	alert := []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x32}

	// The upstream reads the Client Hello and answers it with an alert.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	clientHello := []byte(config.FakeClientHello)
	gotHello := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		hello := make([]byte, len(clientHello))
		_, _ = io.ReadFull(conn, hello)
		gotHello <- hello
		_, _ = conn.Write(alert)
	}()

	var logs bytes.Buffer
	base := &config.RuntimeConfig{}
	base.Conn.TCPTimeout = 2 * time.Second
	base.HTTPS.Skip = true
	h := NewConnectHandler(
		zerolog.New(&logs),
		desync.NewTLSDesyncer(zerolog.Nop(), nil, nil, nil, nil),
		server.NewTLSAlertWatcher(),
		nil,
		rule.NewRuleSet(),
		net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
		base,
	)

	upstream := ln.Addr().(*net.TCPAddr)
	client, done := runConnect(t, h, &proto.SOCKS5Request{
		Cmd:  proto.SOCKS5CmdConnect,
		ATYP: proto.SOCKS5AddrTypeIPv4,
		IP:   upstream.IP,
		Port: upstream.Port,
	})
	require.Equal(t, byte(proto.SOCKS5RCodeSuccess), readReply(t, client))
	_, err = client.Write(clientHello)
	require.NoError(t, err)

	reply, err := io.ReadAll(client)
	require.NoError(t, err)
	assert.Equal(t, alert, reply, "the client gets the alert unchanged")
	assert.Equal(t, clientHello, <-gotHello)
	<-done

	var warned map[string]any
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var entry map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &entry))
		if entry["alert"] != nil {
			warned = entry
		}
	}
	require.NotNil(t, warned, "the alert is logged")
	assert.Equal(t, "warn", warned["level"])
	assert.Equal(t, "decode_error", warned["alert"])
	assert.Equal(t, upstream.String(), warned["dst"])
	assert.NotEmpty(t, warned["sni"])
	assert.Contains(t, warned["message"], "spoofdpi probe "+warned["sni"].(string))
}

func TestConnectHandler_Handle_PlainTCPReplyIsNotWatched(t *testing.T) {
	alert := []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x32}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = io.ReadFull(conn, make([]byte, 4))
		_, _ = conn.Write(alert)
	}()

	var logs bytes.Buffer
	base := &config.RuntimeConfig{}
	base.Conn.TCPTimeout = 2 * time.Second
	h := NewConnectHandler(
		zerolog.New(&logs),
		desync.NewTLSDesyncer(zerolog.Nop(), nil, nil, nil, nil),
		server.NewTLSAlertWatcher(),
		nil,
		rule.NewRuleSet(),
		net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
		base,
	)

	upstream := ln.Addr().(*net.TCPAddr)
	client, done := runConnect(t, h, &proto.SOCKS5Request{
		Cmd:  proto.SOCKS5CmdConnect,
		ATYP: proto.SOCKS5AddrTypeIPv4,
		IP:   upstream.IP,
		Port: upstream.Port,
	})
	require.Equal(t, byte(proto.SOCKS5RCodeSuccess), readReply(t, client))
	_, err = client.Write([]byte("ping"))
	require.NoError(t, err)

	reply, err := io.ReadAll(client)
	require.NoError(t, err)
	assert.Equal(t, alert, reply)
	<-done
	assert.NotContains(t, logs.String(), "TLS alert")
}
