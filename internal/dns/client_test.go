package dns

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/config"
)

// startUDPServer runs a DNS server on loopback that answers every A query
// with 192.0.2.1 after delay. A negative delay means it never answers.
func startUDPServer(t *testing.T, delay time.Duration) net.TCPAddr {
	t.Helper()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			if delay < 0 {
				continue
			}

			req := new(dns.Msg)
			if err := req.Unpack(buf[:n]); err != nil {
				continue
			}
			resp := new(dns.Msg)
			resp.SetReply(req)
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   req.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				A: net.IPv4(192, 0, 2, 1),
			})
			out, err := resp.Pack()
			if err != nil {
				continue
			}

			go func() {
				time.Sleep(delay)
				_, _ = conn.WriteTo(out, from)
			}()
		}
	}()

	addr := conn.LocalAddr().(*net.UDPAddr)
	return net.TCPAddr{IP: addr.IP, Port: addr.Port}
}

func udpOptions(addr net.TCPAddr, timeout time.Duration) *config.DNSOptions {
	opts := config.DefaultConfig().DNS
	opts.Mode = config.DNSModeUDP
	opts.Addr = addr
	opts.QType = config.DNSQueryIPv4
	opts.Timeout = timeout
	return &opts
}

func TestResolve_UDPWaitsUpToTimeout(t *testing.T) {
	t.Parallel()

	// The answer arrives after both the 2s default of dns.Client and 3s,
	// but within the configured timeout.
	opts := udpOptions(startUDPServer(t, 3200*time.Millisecond), 5*time.Second)
	c := NewClient(zerolog.Nop(), opts)

	addrs, err := c.Resolve(context.Background(), opts, "example.com")
	require.NoError(t, err)
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("192.0.2.1")}, addrs)
}

func TestResolve_UDPStopsAtTimeout(t *testing.T) {
	t.Parallel()

	opts := udpOptions(startUDPServer(t, -1), 200*time.Millisecond)
	c := NewClient(zerolog.Nop(), opts)

	start := time.Now()
	_, err := c.Resolve(context.Background(), opts, "example.com")
	assert.Error(t, err)
	assert.Less(t, time.Since(start), time.Second)
}

func TestResolve_IPLiteral(t *testing.T) {
	t.Parallel()

	opts := udpOptions(net.TCPAddr{}, time.Second)
	c := NewClient(zerolog.Nop(), opts)

	addrs, err := c.Resolve(context.Background(), opts, "2001:db8::1")
	require.NoError(t, err)
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("2001:db8::1")}, addrs)
}
